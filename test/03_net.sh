#!/usr/bin/env bash
# net: per-process network connection tracing (netlink; root + Linux).
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"; . "$DIR/lib_live.sh"
section "net"
if is_darwin; then assert_stub net
else live_test "net" gen_net 'curl|example|:80|:443' -- net
fi
print_summary
