#!/usr/bin/env bash
# net: per-process network connection tracing. Linux uses netlink socket
# diag + conntrack and catches connections as they're created; darwin
# polls `lsof -nP -i` and catches connections that live longer than the
# poll interval. The live_test below runs on both — gen_net opens a real
# TCP+TLS connection that is long-lived enough to be visible.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"; . "$DIR/lib_live.sh"
section "net"

if is_darwin && ! is_root; then
  # net polling works without root on darwin (for own-user sockets);
  # live_test still skips off-root for uniformity. Sanity-check here
  # that the tracer is no longer the Linux-only stub.
  o="$(run_timeout 2 "$TRACEP" net 2>&1 || true)"
  assert_not_contains "net: darwin no longer prints Linux-only stub" "only supported on Linux" "$o"
  assert_not_contains "net: darwin no panic" "panic:" "$o"
fi

live_test "net" gen_net 'curl|example|:80|:443' -- net
print_summary
