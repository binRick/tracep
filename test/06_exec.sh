#!/usr/bin/env bash
# exec: per-process exec() tracing. Linux uses the netlink proc connector
# and catches every exec; darwin polls proc_listallpids and catches
# longer-lived processes only (see exec_darwin.go). The live_test below
# runs on both — gen_exec includes backgrounded sleeps so the assertion
# holds whether the tracer is event-driven or polling.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"; . "$DIR/lib_live.sh"
section "exec"

if is_darwin && ! is_root; then
  # darwin exec works without root (for own-user processes); live_test
  # below still skips off-root for uniformity. Sanity-check here that
  # the tracer is no longer the Linux-only stub.
  o="$(run_timeout 2 "$TRACEP" exec 2>&1 || true)"
  assert_not_contains "exec: darwin no longer prints Linux-only stub" "only supported on Linux" "$o"
  assert_not_contains "exec: darwin no panic" "panic:" "$o"
fi

live_test "exec" gen_exec 'sleep|true|uname|exec|/bin/|/usr/bin/' -- exec
print_summary
