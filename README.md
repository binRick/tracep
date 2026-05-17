# tracep

Trace a process's network, TLS, DNS, and exec activity — one self-contained Go binary.

`tracep` unifies five previously-separate tools into a single zero-dependency
(stdlib-only) Linux binary with a subcommand per tracer:

| Command | What it traces | Mechanism |
|---|---|---|
| `tracep net`  | per-process network connections | netlink socket diag + `/proc` |
| `tracep tls`  | per-process TLS reads/writes & SNI | `libssl` uprobes |
| `tracep dns`  | per-process DNS queries & answers | raw `AF_PACKET` socket |
| `tracep exec` | per-process `exec()` syscalls | netlink proc connector |
| `tracep ca`   | a host's TLS CA certificate chain | outbound TLS dial |

Each subcommand keeps the exact flags and behaviour of its original
`proc-trace-*` / `tls-ca-fetch` tool — run `tracep <command> -h` for details.

## Build

```sh
make            # build ./tracep for the host
make linux      # cross-compile static linux/amd64 + linux/arm64 into dist/
```

`tracep` uses raw `syscall` netlink/AF_PACKET and `/proc` parsing, so the
tracers **run on Linux only**. It cross-compiles from any platform.

## Usage

```sh
sudo tracep net              # every process's connections, live
sudo tracep dns -p 1234      # DNS queries from PID 1234 only
sudo tracep dns -j | jq .    # DNS as line-delimited JSON
sudo tracep exec             # every exec() across the system
tracep ca example.com -o -   # dump example.com's CA chain as PEM
```

The four live tracers need root (`CAP_NET_RAW` / `CAP_NET_ADMIN`); `ca` does not.

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

### Test cases

| Suite | What it verifies |
|---|---|
| `01_dispatch` | No-args exits 2 with usage; `-h/--help/help` exit 0 and list every subcommand; `-v/--version/version` print the name; an unknown command exits 2 and is named; **all five subcommands are routable** (regression for the dispatcher). |
| `02_ca` | No-host exits 1 with usage; `-version` prints a version; **flags after the hostname are accepted** (`ca github.com -o -` — regression for the arg-permute fix); a live fetch of `github.com` emits a valid `BEGIN/END CERTIFICATE` block; `-o FILE` writes that PEM to disk; a bad host fails cleanly without hanging or panicking. |
| `03_net` | As root: tracer starts without a privilege error, captures generated `curl` traffic, and never panics. |
| `04_tls` | As root: a **real captured handshake event** (`SSL_write`/`SSL_read` or the SNI host) is observed — not merely the startup banner. |
| `05_dns` | `dns -h` does **not** panic with `flag redefined` (regression for the global-flag-collision bug found during the merge); usage renders; live queries are captured in both human and `-j` JSON form. |
| `06_exec` | As root: generated `exec()`s (`/bin/true`, `uname`, …) appear in the stream. |

### Notes on reliability

The four live tracers are timing-sensitive (they race tracer startup
against generated traffic, and `tls` needs ~2 s to arm its uprobes).
`lib_live.sh` waits for the probes to attach and retries a capture up to
three times before failing, so the suite is deterministic without masking
a genuinely broken tracer. On non-root or non-Linux hosts the live suites
**skip** (not fail) with a clear message; `01_dispatch` and `02_ca` run
anywhere.

Latest run: **54/54 checks green** on Linux 6.12 x86-64.

## Origin

Consolidated from `proc-trace-net`, `proc-trace-tls`, `proc-trace-dns`,
`proc-trace-exec`, and `tls-ca-fetch`. Tracer source is preserved under
`internal/` (only `package`/`main` renamed, plus per-subcommand `flag.FlagSet`
isolation so the merged binary doesn't share global flag state); `main.go`
only dispatches.
