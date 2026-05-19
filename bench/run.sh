#!/usr/bin/env bash
# bench/run.sh — Go vs C benchmark for every tracep mode.
#
# Drives each tracer with a deterministic *local* workload and reports
# CPU, peak RSS and thread count. The four live tracers
# (dns/net/tls/exec) are Linux-only and need root; `ca` is a one-shot
# tool measured via getrusage. Run via `make benchmark`.
#
# Env overrides:
#   GO_BIN (default ./tracep)   C_BIN (default ./c/tracep)
#   N_DNS=600 N_NET=800 N_TLS=200 N_EXEC=3000 N_CA=30
set -u

GO_BIN=${GO_BIN:-./tracep}
C_BIN=${C_BIN:-./c/tracep}
N_DNS=${N_DNS:-600}; N_NET=${N_NET:-800}; N_TLS=${N_TLS:-200}
N_EXEC=${N_EXEC:-3000}; N_CA=${N_CA:-30}

OS=$(uname -s)
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
HERE=$(cd "$(dirname "$0")" && pwd)
TLSPORT=8443; NETPORT=18099
TMP=$(mktemp -d); SRV_TLS=""; SRV_NET=""
TRACEFS=/sys/kernel/debug/tracing

have(){ command -v "$1" >/dev/null 2>&1; }
note(){ printf '  %s\n' "$*" >&2; }

cleanup(){
  [ -n "$SRV_TLS" ] && kill "$SRV_TLS" 2>/dev/null
  [ -n "$SRV_NET" ] && kill "$SRV_NET" 2>/dev/null
  [ -w "$TRACEFS/uprobe_events" ] && : > "$TRACEFS/uprobe_events" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# ── binaries ────────────────────────────────────────────────────────────────
BINS=(); NAMES=()
if [ -x "$GO_BIN" ]; then BINS+=("$GO_BIN"); NAMES+=(Go)
else note "Go binary not found ($GO_BIN) — skipping Go (set GO_BIN=...)"; fi
if [ -x "$C_BIN" ]; then BINS+=("$C_BIN"); NAMES+=(C)
else note "C binary not found ($C_BIN)"; fi
[ ${#BINS[@]} -eq 0 ] && { echo "no binaries to benchmark" >&2; exit 1; }

# ── local test servers ──────────────────────────────────────────────────────
start_tls(){
  have openssl || { note "openssl missing — skipping tls/ca"; return 1; }
  openssl req -x509 -newkey rsa:2048 -keyout "$TMP/k.pem" -out "$TMP/c.pem" \
    -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1 || return 1
  openssl s_server -quiet -accept $TLSPORT -cert "$TMP/c.pem" -key "$TMP/k.pem" \
    -www >/dev/null 2>&1 & SRV_TLS=$!
  sleep 1; kill -0 "$SRV_TLS" 2>/dev/null
}
start_net(){
  have python3 || { note "python3 missing — skipping net"; return 1; }
  python3 -c 'import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(512)
while True:
    try: c,_=s.accept(); c.close()
    except OSError: break' "$NETPORT" >/dev/null 2>&1 & SRV_NET=$!
  sleep 0.5; kill -0 "$SRV_NET" 2>/dev/null
}

# ── workloads ───────────────────────────────────────────────────────────────
w_dns(){  for i in $(seq "$N_DNS");  do getent hosts "h$i.example.invalid" >/dev/null 2>&1; done; }
w_net(){  for i in $(seq "$N_NET");  do (exec 9<>/dev/tcp/127.0.0.1/$NETPORT) 2>/dev/null; exec 9>&- 2>/dev/null; done; }
w_tls(){  for i in $(seq "$N_TLS");  do curl -sk "https://127.0.0.1:$TLSPORT/" -o /dev/null --max-time 3; done; }
w_exec(){ for i in $(seq "$N_EXEC"); do /bin/true; done; }

# ── daemon-mode measurement (Linux, /proc) ──────────────────────────────────
bench_daemon(){ # name bin mode attach workloadfn
  local name=$1 bin=$2 mode=$3 attach=$4 wl=$5
  [ "$mode" = tls ] && [ -w "$TRACEFS/uprobe_events" ] && : > "$TRACEFS/uprobe_events" 2>/dev/null
  "$bin" "$mode" >/dev/null 2>&1 & local p=$!
  sleep "$attach"
  if [ ! -r "/proc/$p/stat" ]; then printf "%-4s %-4s | (failed to start)\n" "$name" "$mode"; return; fi
  $wl
  sleep 1
  local cpu rss thr
  cpu=$(awk '{printf "%.2f",($14+$15)/'"$HZ"'}' "/proc/$p/stat" 2>/dev/null)
  rss=$(awk '/^VmHWM:/{print $2}' "/proc/$p/status" 2>/dev/null)
  thr=$(awk '/^Threads:/{print $2}' "/proc/$p/status" 2>/dev/null)
  kill -TERM "$p" 2>/dev/null; sleep 0.5; kill -KILL "$p" 2>/dev/null; wait "$p" 2>/dev/null
  printf "%-4s %-4s | %7ss | %8s KB | %s\n" "$name" "$mode" "$cpu" "$rss" "$thr"
}

bench_ca(){ # name bin
  local name=$1 bin=$2
  printf "%-4s ca   | " "$name"
  python3 "$HERE/rusage.py" "$N_CA" "$bin" ca 127.0.0.1 -port $TLSPORT -o -
}

# ── run ─────────────────────────────────────────────────────────────────────
echo "tracep benchmark — $OS, Go vs C  (binaries: ${NAMES[*]})"
echo "bin  mode | CPU      | peak RSS    | threads / [ca: wall cpu rss]"
echo "----------+----------+-------------+-----------------------------"

if [ "$OS" = Linux ]; then
  if [ "$(id -u)" -ne 0 ]; then
    note "not root — dns/net/tls/exec need root; running ca only"
  else
    start_net && for i in "${!BINS[@]}"; do bench_daemon "${NAMES[$i]}" "${BINS[$i]}" net  1.5 w_net;  done
    start_tls; TLS_OK=$?
    for i in "${!BINS[@]}"; do bench_daemon "${NAMES[$i]}" "${BINS[$i]}" dns  1.5 w_dns;  done
    [ ${TLS_OK:-1} -eq 0 ] && for i in "${!BINS[@]}"; do bench_daemon "${NAMES[$i]}" "${BINS[$i]}" tls 3.5 w_tls; done
    for i in "${!BINS[@]}"; do bench_daemon "${NAMES[$i]}" "${BINS[$i]}" exec 1.5 w_exec; done
  fi
else
  note "$OS: net/tls/exec are Linux-only stubs; dns needs root — benchmarking ca"
fi

# ca everywhere (start a TLS server if not already up)
if [ -z "$SRV_TLS" ]; then start_tls; fi
if [ -n "$SRV_TLS" ] && have python3; then
  for i in "${!BINS[@]}"; do bench_ca "${NAMES[$i]}" "${BINS[$i]}"; done
else
  note "skipping ca (need openssl + python3)"
fi
