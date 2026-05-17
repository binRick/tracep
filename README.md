# tracep

Trace a process's network, TLS, DNS, and exec activity — one self-contained Go binary.

`tracep` unifies five previously-separate tools into a single zero-dependency
(stdlib-only) Linux binary with a subcommand per tracer:

| Command | What it traces |
|---|---|
| `tracep net`  | per-process network connections (netlink) |
| `tracep tls`  | per-process TLS handshakes |
| `tracep dns`  | per-process DNS queries (AF_PACKET) |
| `tracep exec` | per-process exec syscalls (netlink) |
| `tracep ca`   | fetch a host's TLS CA chain |

Each subcommand keeps the exact flags and behaviour of its original
`proc-trace-*` / `tls-ca-fetch` tool — run `tracep <command> -h` for details.

## Build

```sh
make            # build ./tracep for the host
make linux      # cross-compile static linux/amd64 + linux/arm64 into dist/
```

`tracep` uses raw `syscall` netlink/AF_PACKET and `/proc` parsing, so it
**runs on Linux only**. It cross-compiles from any platform.

## Usage

```sh
sudo tracep net              # all processes' connections
sudo tracep dns -p 1234      # DNS queries from PID 1234
sudo tracep exec -j          # exec syscalls, JSON output
tracep ca example.com        # dump example.com's CA chain to PEM
```

Most tracers need `CAP_NET_ADMIN`/`CAP_NET_RAW` (run as root).

## Origin

Consolidated from `proc-trace-net`, `proc-trace-tls`, `proc-trace-dns`,
`proc-trace-exec`, and `tls-ca-fetch`. Tracer source is preserved verbatim
under `internal/`; `main.go` only dispatches.
