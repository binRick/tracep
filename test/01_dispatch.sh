#!/usr/bin/env bash
# Dispatcher: argument routing, help, version, unknown command.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"

section "dispatch"

o="$("$TRACEP" 2>&1)"; rc=$?
assert_eq 2 "$rc" "no args exits 2"
assert_contains "no args prints usage" "commands:" "$o"

for h in -h --help help; do
  o="$("$TRACEP" "$h" 2>&1)"; rc=$?
  assert_eq 0 "$rc" "'$h' exits 0"
  assert_contains "'$h' lists subcommands" "trace per-process DNS queries" "$o"
done

for v in -v --version version; do
  o="$("$TRACEP" "$v" 2>&1)"; rc=$?
  assert_eq 0 "$rc" "'$v' exits 0"
  assert_contains "'$v' prints name" "tracep" "$o"
done

o="$("$TRACEP" bogus 2>&1)"; rc=$?
assert_eq 2 "$rc" "unknown command exits 2"
assert_contains "unknown command names it" 'unknown command "bogus"' "$o"

# every advertised subcommand must be routable (-h must not say "unknown")
for s in net tls dns exec ca; do
  o="$("$TRACEP" "$s" -h 2>&1)"
  assert_not_contains "subcommand '$s' is routed" "unknown command" "$o"
done

print_summary
