#!/usr/bin/env bash
# exec: per-process exec() syscall tracing (netlink proc connector; root + Linux).
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"; . "$DIR/lib_live.sh"
section "exec"
if is_darwin; then assert_stub exec
else live_test "exec" gen_exec 'true|uname|exec|/bin/|/usr/bin/' -- exec
fi
print_summary
