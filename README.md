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
make            # build ./tracep for the host (Go — default)
make c          # build the C port -> ./c/tracep
make all        # build both
make test       # run the black-box suite against each build
make linux      # cross-compile static linux/amd64 + linux/arm64 into dist/
make darwin     # cross-compile macOS amd64 + arm64 into dist/
```

One Makefile drives both implementations; the Go cross-compile/release
targets are Go-only and unchanged.

The binary builds and runs on Linux and macOS. The Linux-only tracers
(`net`/`tls`/`exec`) are gated behind `//go:build linux`; on macOS they
are present but exit with a Linux-only message, while `ca` and `dns`
(BPF) work natively. It cross-compiles from any platform.

There are **two implementations** — the reference Go binary and a
behaviour-identical C port in `c/` — compared in detail under
[Two implementations: Go and C](#two-implementations-go-and-c).

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

In addition, `make unit` runs Go unit tests. The macOS BPF record-framing
(`bpf_hdr` offsets + `BPF_WORDALIGN` between records) is the most
error-prone part of the platform code and cannot be exercised without
root + `/dev/bpf`, so it is covered deterministically by
`capture_darwin_test.go` (single/aligned-header/multi-record-with-padding/
exact-fit/malformed cases).

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

Latest runs (**both implementations**, same black-box suite): **54/54
green** on Linux 6.12 x86-64; **43/43 green** on macOS (arm64,
unprivileged — dns BPF capture skipped without root).

## Two implementations: Go and C

`tracep` exists twice. The **Go** binary (`main.go` + `internal/`) is the
reference. The **C** port (`c/`) is a faithful, behaviour-for-behaviour
re-implementation — same flags, same output, same ANSI/emoji, same error
text — that passes the *identical* black-box test suite (54/54 Linux,
43/43 macOS). Build the C version with `cd c && make`.

Both make the same platform trade-offs: `net`/`tls`/`exec` are Linux-only
(stub out elsewhere), `dns` adds a macOS `/dev/bpf` backend, `ca` is
cross-platform.

### Lines of code

Total source (excluding the shared bash test suite):

| Tracer    | Go (lines) | C (lines) | Notes |
|-----------|-----------:|----------:|-------|
| dispatch  |   73 | 62 + **173** shared¹ | ¹`c/common.{c,h}` (color, isatty, shquote) |
| `dns`     | 1219 |  652 | Go split across 11 files (help + per-OS); C consolidates it |
| `net`     | 1074 | 1267 | C hand-walks netlink/NLA + a hash map for connDB |
| `tls`     |  795 |  983 | C uses POSIX `regex.h`; manual ftrace fd plumbing |
| `exec`    |  730 | 1000 | C hand-walks the proc-connector netlink stream |
| `ca`      |  233 |  738 | **starkest gap** — see below |
| **Total** | **4026** | **4813** | code-only (no blank/comment): **3262** vs **3918** |

The C port is ~20% larger overall. Three tracers (`net`/`tls`/`exec`) are
modestly bigger because work the Go stdlib does for free
(`syscall.ParseNetlinkMessage`, `regexp`, `encoding/binary`, `net.IP`,
goroutines, maps) becomes explicit C. `dns` is actually *smaller* in C —
the Go version is fragmented across many small per-OS files. `ca` is the
extreme: **233 → 738 lines**, because Go's `crypto/tls` + `net/http` +
`crypto/x509` collapse a TLS dial, chain walk, AIA fetch and PEM encode
into a handful of calls; in C that is OpenSSL boilerplate plus a
hand-written HTTP client.

### Benchmarks

Measured on `mia` (Linux 6.12 x86-64, kernel-6.12). Go: cross-compiled
static, stripped (`-s -w`). C: GCC 14, `-O2`, dynamically linked. Both
pass the **identical** black-box suite there — **54/54 green** for each
(`make test-c`; Go via the suite vs the cross-compiled binary). Figures
are the median of repeated runs.

| Metric | Go | C | |
|---|---:|---:|---|
| Binary size                 | 6,676,642 B (6.4 MB) | 108,528 B (106 KB) | C ≈ **61× smaller** |
| Runtime dependencies        | none (static)        | libc + libssl/libcrypto/libz | Go is copy-anywhere |
| Startup (200× `-v`)         | ~2.6–3.2 ms | ~1.8–2.2 ms | C ≈ **1.4× faster** |
| RSS at rest (`dns`)         | 5,896 KB | 2,808 KB | C ≈ **2.1× leaner** |
| Threads at rest             | 7 (GC/sched/sysmon) | 1 | — |
| CPU for a fixed DNS workload¹ | ~3.4–3.8 s | ~0.34 s | Go ≈ **10× more CPU** |
| Peak RSS under that load    | ~12.4 MB | ~15.5 MB | **Go leaner here** |

¹1,200 lookups while capturing all host traffic via `AF_PACKET`;
process CPU = (utime+stime) from `/proc/<pid>/stat`. (One outlier run hit
31 s for Go during a host-traffic burst — excluded; the ~10× figure is
the stable, repeatable result.)

The headline is **CPU under packet load**: Go burns roughly an order of
magnitude more CPU than C to parse the same traffic, because every packet
goes through allocation + GC (slices, strings, maps) while the C parser
is zero-allocation. That, plus a 61× smaller binary, ~1.4× faster
startup, half the resting memory and a single thread, is the C case.

The honest counter-points: startup difference is small (process spawn
dominates) and **memory crosses over under load** — C's fixed 64 K-slot
port/transaction tables page in and its peak RSS overtakes Go's
GC-managed maps. And Go's binary, while ~60× larger, has *zero* runtime
dependencies, whereas C's `ca` needs OpenSSL present.

#### Every mode, Linux (`mia`, 6.12 x86-64)

The four live tracers driven by a fixed local workload while running
(median of repeated runs; CPU = (utime+stime) from `/proc/<pid>/stat`,
RSS = peak `VmHWM`):

| Tracer | Workload | CPU Go | CPU C | RSS Go | RSS C | Threads Go→C |
|---|---|---:|---:|---:|---:|---:|
| `dns`  | 1,200 lookups, all traffic | ~3.4–3.8 s | **~0.34 s** | ~12.4 MB | 15.5 MB | 9 → **1** |
| `net`  | 1,000 TCP connects | **~1.7 s** | ~1.9 s | 11.5 MB | **3.6 MB** | 8 → **1** |
| `tls`  | 300 local TLS handshakes | ~0.9 s | **0.45 s** | 12.3 MB | **4.8 MB** | 9 → **1** |
| `exec` | 4,000 `exec()`s | ~0.8 s | **0.58 s** | 11.8 MB | **3.6 MB** | 7 → **1** |

`ca` is a one-shot tool, not a daemon — measured differently, as 50
cert-chain fetches against a local TLS server (`getrusage` per
invocation):

| `ca` (per fetch) | Wall | CPU | Peak RSS |
|---|---:|---:|---:|
| Go | 42.1 ms | 43.1 ms | 12.8 MB |
| C  | **14.0 ms** | **12.4 ms** | **10.6 MB** |

The pattern holds across all five: C is **single-threaded** vs Go's 7–9
runtime threads and uses **~2.6–3.3× less resident memory** for the
event-driven tracers. CPU favours C on `tls`/`exec` (~1.4–2×),
dramatically on `dns` (~10×, the packet-flood zero-alloc case) and on
one-shot `ca` (~3× — Go's runtime init dominates a short-lived process).
`net` is the lone near-tie — bound by the `/proc` inode→PID scan on
every conntrack event, a syscall cost identical in both languages.
(`dns` is the one place C's peak RSS exceeds Go's, from its fixed
64 K-slot tables; everywhere else C's static tables stay well below
Go's runtime + GC heap.)

#### macOS (this host, 26.2 arm64)

Only `ca` and `dns` run natively on macOS; `net`/`tls`/`exec` are
Linux-only stubs (print the message and exit instantly), and `dns`'s
`/dev/bpf` capture needs root (skipped unprivileged, as in the suite).
So `ca` is the representative cross-platform workload:

| | Binary size | `ca` wall/fetch | `ca` CPU/fetch | `ca` peak RSS |
|---|---:|---:|---:|---:|
| Go | 5,919,042 B (5.6 MB) | 18.3 ms | 7.3 ms | 15.2 MB |
| C  | **75,480 B (74 KB)** | **10.4 ms** | 8.8 ms | **7.2 MB** |

Same shape as Linux: the C binary is ~79× smaller and ~1.8× faster
per fetch with half the resident memory; CPU is near-parity here (macOS
LibreSSL vs Go's `crypto/tls` differ less than on Linux). The
`net`/`tls`/`exec` stubs are sub-millisecond either way — not a
meaningful benchmark, just a portability guarantee.

### Pros / cons

| | Go | C |
|---|---|---|
| **Binary size**        | 6.4 MB | **106 KB** |
| **Dependencies**       | **none** (single static file) | libssl/libcrypto for `ca` |
| **CPU under load**     | ~10× more (per-packet GC) | **zero-alloc parse** |
| **Memory at rest**     | ~5.9 MB RSS, 7 threads | **~2.8 MB RSS, 1 thread** |
| **Memory under load**  | **~12 MB** (GC-managed maps) | ~15 MB (fixed 64 K tables) |
| **Cross-compilation**  | **trivial** (`GOOS=… go build`) | per-target toolchain + headers |
| **Code volume**        | **~20% less**, esp. `ca` | more explicit boilerplate |
| **Memory safety**      | **GC, bounds-checked** | manual buffers, hand-rolled maps |
| **Reviewability**      | stdlib hides the syscalls | **every syscall is visible** |
| **Edit/build loop**    | fast, batteries-included | small deps, but more to maintain |

### Which to use

Prefer **Go** for distribution and day-to-day use: one dependency-free
binary that cross-compiles anywhere, with the safety the GC and stdlib
buy. Reach for **C** when binary size, startup, or **sustained CPU under
heavy packet/event load** matter (it parses the same DNS traffic for ~⅒
the CPU), or for initramfs/tiny-container/embedded targets, or when you
want the kernel interactions spelled out with nothing between the code
and the syscall — accepting OpenSSL as `ca`'s one runtime dependency, a
larger memory footprint under load, and more surface to maintain.

## Origin

Consolidated from `proc-trace-net`, `proc-trace-tls`, `proc-trace-dns`,
`proc-trace-exec`, and `tls-ca-fetch`. Tracer source is preserved under
`internal/` (only `package`/`main` renamed, plus per-subcommand `flag.FlagSet`
isolation so the merged binary doesn't share global flag state); `main.go`
only dispatches.
