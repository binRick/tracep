# tracep

Trace a process's network, TLS, DNS, and exec activity — one self-contained Go binary.

`tracep` unifies five previously-separate tools into a single zero-dependency
(stdlib-only) binary with a subcommand per tracer:

| Command | What it traces | Mechanism | Linux | macOS |
|---|---|---|:--:|:--:|
| `tracep net`  | per-process network connections | netlink socket diag + `/proc` | ✅ | ❌ |
| `tracep tls`  | per-process TLS reads/writes & SNI | `libssl` uprobes | ✅ | ❌ |
| `tracep dns`  | per-process DNS queries & answers | `AF_PACKET` (Linux) / BPF (macOS) | ✅ | ✅¹ |
| `tracep exec` | per-process `exec()` syscalls | netlink proc connector | ✅ | ❌ |
| `tracep ca`   | a host's TLS CA certificate chain | outbound TLS dial | ✅ | ✅ |

¹ macOS `dns` captures via `/dev/bpf` and shows queries **without** process
attribution (pid `0`, name `?`) — there is no portable socket→PID map off
Linux. On macOS, `net`/`tls`/`exec` exit immediately with a clear
"Linux-only" message; the binary still builds and runs everywhere.

Each subcommand keeps the exact flags and behaviour of its original
`proc-trace-*` / `tls-ca-fetch` tool — run `tracep <command> -h` for details.

## Build

```sh
make            # build ./tracep for the host
make linux      # cross-compile static linux/amd64 + linux/arm64 into dist/
make darwin     # cross-compile macOS amd64 + arm64 into dist/
```

The binary builds and runs on Linux and macOS. The Linux-only tracers
(`net`/`tls`/`exec`) are gated behind `//go:build linux`; on macOS they
are present but exit with a Linux-only message, while `ca` and `dns`
(BPF) work natively. It cross-compiles from any platform.

## Usage

```sh
sudo tracep net              # every process's connections, live
sudo tracep dns -p 1234      # DNS queries from PID 1234 only
sudo tracep dns -j | jq .    # DNS as line-delimited JSON
sudo tracep exec             # every exec() across the system
tracep ca example.com -o -   # dump example.com's CA chain as PEM

sudo tracep dns              # macOS: same, via /dev/bpf (no PID column)
tracep ca example.com        # macOS: works natively, no privileges
```

The live tracers need root (`CAP_NET_RAW` / `CAP_NET_ADMIN` on Linux,
`/dev/bpf` access on macOS); `ca` needs no privileges on any platform.

## What each tracer finds — in detail

All samples below are real output captured on a live Linux host
(`6.12.0`, x86-64) during the test run.

### `tracep net` — connection attribution

Reads the kernel socket table via netlink and joins each socket back to its
owning PID/command through `/proc/<pid>/fd`. You see **who** talked to
**where**, the L4 protocol, and the direction of the flow:

```
  930 dockerd      UDP  172.238.205.61:55189     → 172.233.160.27:53
    ? ?            TCP  47.128.20.131:57804      ← 172.238.205.61:443
    ? ?            TCP  172.18.0.9:54672         ↔ 35.194.67.18:443
```

- `→` outbound, `←` inbound, `↔` established both-ways.
- `? ?` means the socket had no resolvable owner at capture time (kernel
  threads, already-exited processes, or NAT'd container traffic) — it is
  still reported so nothing is silently dropped.
- Container traffic (the `172.18.0.0/16` addresses above) is captured the
  same as host traffic.

### `tracep tls` — TLS visibility without MITM

Attaches uprobes to the system `libssl` and records every `SSL_write` /
`SSL_read`, tagged with PID, command, direction, and the SNI/hostname —
**plaintext-adjacent visibility with no proxy and no key material**:

```
proc-trace-tls dev
  lib : /usr/lib64/libssl.so.3.5.5
  pids: all
Watching 7 probe(s). Press Ctrl-C to stop.

19:36:46.818 3746265 curl TX SSL_write  example.com
19:36:46.889 3746267 curl TX SSL_write  github.com
19:36:47.074 3746269 curl TX SSL_write  example.com
```

`TX` = data the process sent into the TLS session, `RX` = data it read out.
The probe count depends on which `libssl` symbols are present on the host.

### `tracep dns` — query attribution and timing

Opens a raw `AF_PACKET` socket, parses DNS on the wire, and matches each
response back to its request to compute latency:

```
0        ?                A      example.com        → 172.66.147.243 104.20.23.154  41.8ms
0        ?                A      github.com         → 140.82.113.3  0.1ms
```

Columns: PID, command, record type, queried name, answers, round-trip time.
With `-j` it emits one JSON object per query — ideal for piping to `jq` or
shipping to a log pipeline:

```json
{"answers":["104.16.133.229","104.16.132.229"],"latency_ms":35.783,"name":"?","pid":0,"query":"cloudflare.com","rcode":"NOERROR","type":"A"}
```

`rcode` surfaces failures (`NXDOMAIN`, `SERVFAIL`) so DNS problems are visible,
not just successes. (A `?`/`0` owner means the query left via a resolver/stub
whose socket wasn't attributable at capture time.)

### `tracep exec` — every program launch

Subscribes to the netlink **proc connector** and prints each `exec()`
system-wide with PID and full argv — a live audit log of what is being run:

```
  3745740 ls /var/lib/docker/volumes/swaudit-reports/_data/runs/717be26344c160e9b5bcb144/
  3745741 sort
  3745742 diff -u /tmp/prev.list /tmp/now.list
  3745743 grep -E '^\+[^+]'
  3745744 cp /tmp/now.list /tmp/prev.list
```

This catches short-lived processes that `ps`/`top` polling miss entirely —
useful for spotting cron jobs, container entrypoints, and unexpected shell-outs.

### `tracep ca` — certificate chain fetch

Dials the host over TLS and dumps the presented certificate chain as PEM
(no privileges required). Supports `-o FILE` / `-o -`, `-port`, `-all`
(include leaf), `-fetch-root` (resolve the root via AIA), and `-insecure`:

```
→ Connecting to github.com:443 …
Chain received: 3 certificate(s)
──────────────────────────────────────────────────────────────────────
-----BEGIN CERTIFICATE-----
...
```

Flags may appear before or after the hostname (`ca github.com -o -` works).

## Testing

A pure-bash test framework lives in [`test/`](test/). It needs no
dependencies beyond coreutils and runs the binary as a black box.

```sh
TRACEP=/usr/local/bin/tracep test/run.sh          # full suite
TRACEP=/usr/local/bin/tracep test/run.sh 02 05    # only the ca + dns suites
```

`test/run.sh` aggregates every `NN_*.sh` suite and exits non-zero if any
check fails. `lib.sh` provides the assertions; `lib_live.sh` drives the
root-only tracers.

### Test cases — what each one does and what tracep detects

Every suite is a black-box test: it drives the real binary, generates
known activity, and asserts on what tracep reports back. The live suites
(`03`–`06`) run a tracer under a `timeout`, generate matching traffic
mid-window, then inspect the capture.

#### `01_dispatch` — command routing (no privileges, runs anywhere)

The dispatcher itself does no tracing, so these cases verify the merge
plumbing rather than a tracer.

| Test action | What is asserted |
|---|---|
| Run `tracep` with no args | Exits **2** and prints the `commands:` usage block |
| Run `tracep -h`, `--help`, `help` | Each exits **0** and lists every subcommand (e.g. `trace per-process DNS queries`) |
| Run `tracep -v`, `--version`, `version` | Each exits **0** and prints `tracep` + the build version |
| Run `tracep bogus` | Exits **2** and the message names the bad command: `unknown command "bogus"` |
| Run `tracep <sub> -h` for net/tls/dns/exec/ca | None reports `unknown command` → **all five tracers are reachable** (regression: a broken dispatch entry would silently lose a tracer) |

#### `02_ca` — TLS CA chain fetch (no privileges, runs anywhere)

Stimulus is an outbound TLS dial; tracep must extract the server's
certificate chain.

| Test action | What tracep detects / asserts |
|---|---|
| `tracep ca` (no hostname) | Exits **1**, usage mentions `hostname` |
| `tracep ca -version` | Exits **0**, prints a `ca-fetch v0.x` version |
| `tracep ca github.com -o -` | **Flag after positional is accepted** (regression for the arg-permute bug — previously misread `-o` as the port) |
| `tracep ca github.com -o -` (live) | Output contains a real `-----BEGIN CERTIFICATE-----` … `END CERTIFICATE-----` block — tracep parsed github.com's served chain |
| `tracep ca github.com -o /tmp/gh-ca.pem` | The PEM is written to the file on disk |
| `tracep ca no-such-host.invalid -timeout 3` | Fails with non-zero exit **without hanging or panicking** (clean error path) |

If outbound 443 is unavailable the live fetch *skips* (not fails) with a
clear message.

#### `03_net` — connection attribution (root + Linux)

The test runs `tracep net`, then generates `curl http://example.com`
traffic. tracep must observe the connection.

| Test action | What tracep detects / asserts |
|---|---|
| Start `tracep net` as root | No `Hint: run as root` socket error → it has the privileges it needs |
| `curl http://example.com` during the window | Capture is non-empty and contains a matching flow — the `curl` command, `example`, or a `:80`/`:443` endpoint, with its direction arrow (`→`/`←`/`↔`) |
| Throughout | Output never contains `panic:` |

#### `04_tls` — TLS read/write visibility (root + Linux)

Runs `tracep tls` (which arms `libssl` uprobes — given ~3 s to attach),
then drives `curl https://example.com`.

| Test action | What tracep detects / asserts |
|---|---|
| Start `tracep tls` as root | Attaches probes without a privilege error |
| `curl https://example.com` during the window | A **real handshake event** is captured — an `SSL_write`/`SSL_read` line or the SNI host (`example`/`github`), e.g. `… curl TX SSL_write example.com`. The startup banner alone is **not** accepted as a pass |
| Throughout | No `panic:` |

#### `05_dns` — DNS query attribution (root + Linux)

Combines a regression check with live capture.

| Test action | What tracep detects / asserts |
|---|---|
| `tracep dns -h` | Does **not** panic with `flag redefined` (regression for the global-`flag` collision found during the merge) and does not `panic:`; the `USAGE` block renders |
| `dig example.com github.com`, `nslookup cloudflare.com` during the window | Human mode: the queried names / record types appear (`example`, `github`, `cloudflare`, `A`, `AAAA`) |
| Same, with `tracep dns -j` | JSON mode: output is line-delimited objects (`{… "query": …}`) suitable for `jq` |
| Throughout | No `panic:` |

#### `06_exec` — program-launch audit (root + Linux)

Runs `tracep exec`, then launches known short-lived processes.

| Test action | What tracep detects / asserts |
|---|---|
| Start `tracep exec` as root | Subscribes to the proc connector without a privilege error |
| Run `/bin/true` and `uname -a` repeatedly | Those `exec()`s appear in the stream (`true`, `uname`, `/bin/`, `/usr/bin/`) — including processes too short-lived for `ps` polling to catch |
| Throughout | No `panic:` |

### Notes on reliability

The four live tracers are timing-sensitive (they race tracer startup
against generated traffic, and `tls` needs ~2 s to arm its uprobes).
`lib_live.sh` waits for the probes to attach and retries a capture up to
three times before failing, so the suite is deterministic without masking
a genuinely broken tracer.

The suite is OS-aware:

- **Linux** — all six suites run; the four live tracers need root (skip,
  don't fail, otherwise).
- **macOS** — `01_dispatch` and `02_ca` run fully; `net`/`tls`/`exec`
  switch to a **stub assertion** (must exit non-zero with the Linux-only
  message); `05_dns` runs its `-h` regression everywhere and its live
  BPF capture when run as root (skips otherwise).
- Other OSes — live suites skip with a clear message.

Latest runs: **54/54 green** on Linux 6.12 x86-64; **43/43 green** on
macOS (arm64, unprivileged — dns BPF capture skipped without root).

## Origin

Consolidated from `proc-trace-net`, `proc-trace-tls`, `proc-trace-dns`,
`proc-trace-exec`, and `tls-ca-fetch`. Tracer source is preserved under
`internal/` (only `package`/`main` renamed, plus per-subcommand `flag.FlagSet`
isolation so the merged binary doesn't share global flag state); `main.go`
only dispatches.
