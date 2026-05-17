#!/usr/bin/env bash
# tracep test runner — runs every test file and aggregates the result.
#
#   TRACEP=/path/to/tracep test/run.sh            # all suites
#   TRACEP=/path/to/tracep test/run.sh 01 05      # only matching suites
#
# Exit code is non-zero if any case fails.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TRACEP="${TRACEP:-/usr/local/bin/tracep}"

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Z=$'\033[0m'
else B=; G=; R=; Z=; fi

echo "${B}tracep test suite${Z}"
echo "binary : $TRACEP"
echo "version: $("$TRACEP" --version 2>&1)"
echo "host   : $(uname -srm)  uid=$(id -u)"

filter="${*:-}"
total_run=0 total_pass=0 total_fail=0 suites_failed=0

for f in "$DIR"/[0-9][0-9]_*.sh; do
  base="$(basename "$f")"
  if [ -n "$filter" ]; then
    match=0
    for p in $filter; do [[ "$base" == *"$p"* ]] && match=1; done
    [ "$match" = 1 ] || continue
  fi
  # each suite prints its own summary and exits non-zero on failure;
  # capture counts from its final summary line.
  out="$(bash "$f" 2>&1)"; rc=$?
  echo "$out"
  line="$(printf '%s\n' "$out" | grep -E 'ALL PASS|FAILED' | tail -1)"
  p="$(printf '%s' "$line" | grep -oE '[0-9]+/[0-9]+' | head -1)"
  pass="${p%%/*}"; run="${p##*/}"
  total_pass=$((total_pass + ${pass:-0}))
  total_run=$((total_run + ${run:-0}))
  [ "$rc" -ne 0 ] && suites_failed=$((suites_failed+1))
done

total_fail=$((total_run - total_pass))
echo
echo "=========================================="
echo "${B}TOTAL${Z}  ${total_pass}/${total_run} checks passed across all suites"
if [ "$suites_failed" -eq 0 ] && [ "$total_run" -gt 0 ]; then
  echo "${G}${B}SUITE GREEN${Z}"
  exit 0
else
  echo "${R}${B}SUITE RED${Z}  (${suites_failed} suite(s) failed, ${total_fail} check(s) failed)"
  exit 1
fi
