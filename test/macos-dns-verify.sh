#!/usr/bin/env bash
#
# macOS DNS (BPF) end-to-end verification.
#
#   sudo bash test/macos-dns-verify.sh
#
# Builds the binary if needed, runs `tracep dns` against the live /dev/bpf
# device while generating known DNS lookups, then runs the 05_dns suite.
# Prints a single PASS/FAIL summary and exits non-zero on failure so the
# output can be pasted back verbatim.
set -u

# repo root = parent of this script's dir
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2

# Go / tools may not be on root's PATH under sudo.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "──────────────────────────────────────────────"; }

hr
say "tracep macOS dns verification"
say "host : $(uname -srm)"
say "user : $(id -un) (uid=$(id -u))"
hr

if [ "$(id -u)" != 0 ]; then
  say "FAIL: must run as root — use:  sudo bash test/macos-dns-verify.sh"
  exit 2
fi
if [ "$(uname -s)" != Darwin ]; then
  say "FAIL: this script is for macOS; on Linux just run test/run.sh"
  exit 2
fi

# Build (own the binary as the invoking user if possible).
if ! command -v go >/dev/null 2>&1; then
  say "FAIL: 'go' not found on PATH (looked in /opt/homebrew/bin etc.)"
  exit 2
fi
say "building ./tracep …"
if ! go build -o tracep . 2>build.err; then
  say "FAIL: build failed:"; cat build.err; rm -f build.err; exit 2
fi
rm -f build.err
BIN="$PWD/tracep"
say "built: $("$BIN" --version)"
hr

# ── 1. live capture ───────────────────────────────────────────────────
say "[1/2] live BPF capture (≈5s) — generating DNS while tracing"
cap="$(mktemp /tmp/tracep-macdns.XXXXXX)"
"$BIN" dns >"$cap" 2>&1 &
tracer=$!
sleep 2
dig  +short +time=2 github.com      >/dev/null 2>&1
dig  +short +time=2 example.com     >/dev/null 2>&1
nslookup -timeout=2 cloudflare.com  >/dev/null 2>&1
dig  +short +time=2 wikipedia.org   >/dev/null 2>&1
sleep 2
kill "$tracer" 2>/dev/null
wait "$tracer" 2>/dev/null

say "--- first lines of capture ---"
head -8 "$cap"
say "------------------------------"

live_ok=0
if grep -qE 'github|example|cloudflare|wikipedia' "$cap"; then
  say "live capture: PASS (observed a generated query)"
  live_ok=1
else
  say "live capture: FAIL (no expected query seen)"
  say "full capture follows for diagnosis:"
  cat "$cap"
fi
if grep -q 'panic:' "$cap"; then
  say "live capture: FAIL (panic in output)"
  live_ok=0
fi
rm -f "$cap"
hr

# ── 2. 05_dns suite ───────────────────────────────────────────────────
say "[2/2] 05_dns suite (regression + live, as root)"
suite_out="$(TRACEP="$BIN" bash test/run.sh 05 2>&1)"
suite_rc=$?
printf '%s\n' "$suite_out" | grep -E 'ok |FAIL|skip|ALL PASS|FAILED|TOTAL|SUITE'
hr

# ── summary ───────────────────────────────────────────────────────────
if [ "$live_ok" = 1 ] && [ "$suite_rc" = 0 ]; then
  say "RESULT: PASS — macOS dns (BPF) verified end-to-end"
  exit 0
fi
say "RESULT: FAIL — live_ok=$live_ok suite_rc=$suite_rc (paste this whole output)"
exit 1
