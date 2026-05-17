#!/usr/bin/env bash
# tracep test framework — assertion helpers.
# Source this from each test file. Set TRACEP to the binary under test.

TRACEP="${TRACEP:-/usr/local/bin/tracep}"

# counters (exported across sourced files via env when run.sh aggregates)
: "${TESTS_RUN:=0}" "${TESTS_PASS:=0}" "${TESTS_FAIL:=0}"

if [ -t 1 ]; then C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else C_G=; C_R=; C_Y=; C_D=; C_0=; fi

_pass() { TESTS_RUN=$((TESTS_RUN+1)); TESTS_PASS=$((TESTS_PASS+1)); echo "${C_G}ok${C_0}   $1"; }
_fail() {
  TESTS_RUN=$((TESTS_RUN+1)); TESTS_FAIL=$((TESTS_FAIL+1))
  echo "${C_R}FAIL${C_0} $1"
  [ -n "$2" ] && echo "${C_D}     $2${C_0}"
  return 1
}

# assert_eq <expected> <actual> <msg>
assert_eq() {
  if [ "$1" = "$2" ]; then _pass "$3"
  else _fail "$3" "expected [$1] got [$2]"; fi
}

# assert_contains <msg> <needle> -- runs stdin/arg; reads $HAYSTACK
assert_contains() {
  local msg="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then _pass "$msg"
  else _fail "$msg" "output did not contain [$needle]"; fi
}

assert_not_contains() {
  local msg="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then _fail "$msg" "output unexpectedly contained [$needle]"
  else _pass "$msg"; fi
}

assert_match() {
  local msg="$1" re="$2" hay="$3"
  if printf '%s' "$hay" | grep -qE -- "$re"; then _pass "$msg"
  else _fail "$msg" "output did not match /$re/"; fi
}

# run_capture <var-out> <var-rc> -- <cmd...> : run cmd, capture combined output + exit code
run_capture() {
  local _ov="$1" _rv="$2"; shift 3   # drop the literal --
  local _o _rc
  _o="$("$@" 2>&1)"; _rc=$?
  printf -v "$_ov" '%s' "$_o"
  printf -v "$_rv" '%s' "$_rc"
}

# assert_rc <expected-code> <msg> -- <cmd...>
assert_rc() {
  local exp="$1" msg="$2"; shift 3
  local o rc; o="$("$@" 2>&1)"; rc=$?
  if [ "$rc" = "$exp" ]; then _pass "$msg"
  else _fail "$msg" "expected exit $exp got $rc; output: $(printf '%s' "$o" | head -1)"; fi
}

# trace_for <seconds> <outfile> -- <tracep args...> : run a live tracer bounded by timeout,
# capturing stdout+stderr to outfile. Returns immediately after timeout.
trace_for() {
  local secs="$1" of="$2"; shift 3
  timeout "${secs}s" "$TRACEP" "$@" >"$of" 2>&1 &
  echo $!
}

section() { echo; echo "${C_Y}── $* ──${C_0}"; }

print_summary() {
  echo
  echo "──────────────────────────────────────────"
  if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "${C_G}ALL PASS${C_0}  ${TESTS_PASS}/${TESTS_RUN}"
  else
    echo "${C_R}FAILED${C_0}    ${TESTS_PASS}/${TESTS_RUN} passed, ${TESTS_FAIL} failed"
  fi
  [ "$TESTS_FAIL" -eq 0 ]
}
