#!/usr/bin/env bash
# ca: TLS CA chain fetch (no privileges required — pure network).
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"

section "ca"

o="$("$TRACEP" ca 2>&1)"; rc=$?
assert_eq 1 "$rc" "ca with no host exits 1"
assert_contains "ca usage mentions hostname" "hostname" "$o"

o="$("$TRACEP" ca -version 2>&1)"; rc=$?
assert_eq 0 "$rc" "ca -version exits 0"
assert_match "ca -version prints a version" 'ca-fetch v[0-9]' "$o"

# Regression: flags must be accepted *after* positionals (permute).
o="$(timeout 15s "$TRACEP" ca github.com -o - 2>&1)"; rc=$?
assert_not_contains "ca accepts flags after hostname (permute)" "invalid port: -o" "$o"

# Live fetch — needs outbound 443. Skip gracefully if no connectivity.
if "$TRACEP" ca github.com -o - >/tmp/ca.out 2>/tmp/ca.err; then
  o="$(cat /tmp/ca.out)"
  assert_contains "ca github.com emits a PEM cert" "BEGIN CERTIFICATE" "$o"
  assert_contains "ca github.com emits END marker" "END CERTIFICATE" "$o"
  # -o FILE writes a file
  "$TRACEP" ca github.com -o /tmp/gh-ca.pem >/dev/null 2>&1
  assert_match "ca -o FILE writes PEM file" 'BEGIN CERTIFICATE' "$(cat /tmp/gh-ca.pem 2>/dev/null)"
  rm -f /tmp/gh-ca.pem /tmp/ca.out /tmp/ca.err
else
  echo "${C_Y}skip${C_0} ca live fetch (no outbound 443?): $(head -1 /tmp/ca.err)"
fi

# bad host should fail, not hang or panic
o="$(timeout 15s "$TRACEP" ca no-such-host.invalid -timeout 3 2>&1)"; rc=$?
assert_match "ca bad host fails cleanly" '[1-9]' "$rc"
assert_not_contains "ca bad host does not panic" "panic:" "$o"

print_summary
