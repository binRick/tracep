#!/usr/bin/env bash
# dns: per-process DNS query tracing (AF_PACKET; root + Linux).
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"; . "$DIR/lib_live.sh"
section "dns"

# flag isolation regression: dns must not collide with ca's -o flag.
o="$("$TRACEP" dns -h 2>&1)"; rc=$?
assert_not_contains "dns -h does not panic (flag-redefined regression)" "flag redefined" "$o"
assert_not_contains "dns -h does not panic" "panic:" "$o"
assert_contains "dns -h shows usage" "USAGE" "$o"

# JSON mode should emit parseable objects when queries are seen.
live_test "dns" gen_dns 'example|github|cloudflare|A |AAAA' -- dns
live_test "dns-json" gen_dns '\{.*"' -- dns -j

print_summary
