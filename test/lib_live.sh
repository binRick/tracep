#!/usr/bin/env bash
# Helpers for the live (root + Linux) tracer tests.
# These tracers run continuously; we bound them with `timeout`, generate
# matching traffic in the middle of the window, then inspect the capture.

is_root()  { [ "$(id -u)" = 0 ]; }
is_linux() { [ "$(uname -s)" = Linux ]; }

# generators — each produces activity the matching tracer should observe
gen_dns() {
  dig +short +time=2 example.com           >/dev/null 2>&1
  dig +short +time=2 github.com            >/dev/null 2>&1
  nslookup -timeout=2 cloudflare.com       >/dev/null 2>&1
}
gen_net() { curl -s -m 6 -o /dev/null http://example.com 2>/dev/null; }
gen_tls() { curl -s -m 6 -o /dev/null https://example.com 2>/dev/null; }
gen_exec() { for i in 1 2 3 4 5; do /bin/true; /usr/bin/uname -a >/dev/null; done; }

# live_test <label> <gen-fn> <expect-regex> -- <tracep subcmd + args...>
#   Skips (not fails) when not root/Linux. Fails on panic, empty output,
#   or a fatal privilege/socket error while running as root.
live_test() {
  local label="$1" gen="$2" expect="$3"; shift 4
  if ! is_linux; then echo "${C_Y}skip${C_0} $label (not Linux)"; return 0; fi
  if ! is_root;  then echo "${C_Y}skip${C_0} $label (needs root)"; return 0; fi

  # Live syscall/network tracing is timing-sensitive: a single capture can
  # race tracer startup against traffic generation. Retry up to 3 times and
  # keep the first capture that observed the expected activity, so the suite
  # is deterministic without masking a genuinely broken tracer.
  local out="" attempt
  for attempt in 1 2 3; do
    local of; of="$(mktemp /tmp/tracep-live.XXXXXX)"
    timeout 10s "$TRACEP" "$@" >"$of" 2>&1 &
    local pid=$!
    sleep 3               # tls attaches libssl uprobes — needs ~2s to arm
    "$gen"; "$gen"        # generate twice in case the first races startup
    sleep 1.5
    wait "$pid" 2>/dev/null
    out="$(cat "$of")"; rm -f "$of"
    if [ -n "$out" ] && printf '%s' "$out" | grep -qE -- "$expect"; then break; fi
    [ "$attempt" -lt 3 ] && echo "${C_D}     $label: attempt $attempt saw no match, retrying${C_0}"
  done

  assert_not_contains "$label: no panic" "panic:" "$out"
  assert_not_contains "$label: started with privileges (no socket error)" "Hint: run as root" "$out"
  if [ -n "$out" ]; then _pass "$label: produced output"
  else _fail "$label: produced output" "capture was empty after generating traffic"; fi
  assert_match "$label: observed expected activity" "$expect" "$out"
}
