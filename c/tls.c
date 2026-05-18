// tls — capture plaintext TLS traffic via ftrace uprobes on OpenSSL/GnuTLS
// (port of internal/tlstrace).
//
// Attaches uprobes to SSL_read / SSL_write (and their _ex variants) in
// libssl.so using the kernel's ftrace uprobe interface
// (/sys/kernel/debug/tracing). Also uprobes SSL_get_servername / SSL_ctrl
// to capture SNI hostnames. Falls back to /proc/<pid>/net/tcp[6] for IP
// when SNI is unavailable. No eBPF. No ptrace. No kernel modules.
//
// Requires root or CAP_SYS_ADMIN + CAP_DAC_OVERRIDE (for debugfs).
#define _GNU_SOURCE
#include "common.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <regex.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TRACING_BASE   "/sys/kernel/debug/tracing"
#define UPROBE_EVENTS  TRACING_BASE "/uprobe_events"
#define TRACE_PIPE     TRACING_BASE "/trace_pipe"
#define TRACE_ON       TRACING_BASE "/tracing_on"
#define CURRENT_TRACER TRACING_BASE "/current_tracer"

// probeTargets are the symbols we uprobe in libssl.
static const struct {
    const char *symbol;
    bool        is_ret;
    const char *dir;       // "read", "write", or "sni"
    const char *extra_args;// extra ftrace argument spec appended to the probe line
    const char *filter;    // written to the uprobe's filter file (empty = none)
} probe_targets[] = {
    {"SSL_read",           false, "read",  "",                                "" },
    {"SSL_read",           true,  "read",  "",                                "" },
    {"SSL_write",          false, "write", "",                                "" },
    {"SSL_read_ex",        false, "read",  "",                                "" },
    {"SSL_write_ex",       false, "write", "",                                "" },
    // SSL_get_servername returns const char* — capture as uretprobe string.
    {"SSL_get_servername", true,  "sni",   "+0($retval):string",              "" },
    // SSL_ctrl(ssl, cmd=55, 0, hostname) — client-side SNI. Filter cmd==55.
    {"SSL_ctrl",           false, "sni",   "cmd=%si:u64 sni=+0(%cx):string",  "cmd==55"},
};
#define NTARGETS ((int)(sizeof probe_targets / sizeof probe_targets[0]))

// ─── Options ──────────────────────────────────────────────────────────────────

#define MAX_PIDS 256
static int   watch_pids[MAX_PIDS];
static int   watch_n;
static char  libssl_path[PATH_MAX];
static char  out_file[PATH_MAX];
static bool  color_force;
static bool  color_mode;
static bool  quiet_mode;
static bool  show_errors = true;   // -Q clears (kept for parity; unused like Go)
static bool  size_only;            // -s (kept for parity; unused like Go)
static bool  verbose;
static bool  no_reverse_dns;
static FILE *out;                  // default stdout; -o appends

// ─── Per-PID SNI cache ────────────────────────────────────────────────────────

#define MAX_SNI 1024
static struct { int pid; char host[256]; bool set; } sni_cache[MAX_SNI];

static void set_sni(int pid, const char *host) {
    int free_slot = -1;
    for (int i = 0; i < MAX_SNI; i++) {
        if (sni_cache[i].set && sni_cache[i].pid == pid) {
            snprintf(sni_cache[i].host, sizeof sni_cache[i].host, "%s", host);
            return;
        }
        if (free_slot < 0 && !sni_cache[i].set) free_slot = i;
    }
    if (free_slot < 0) free_slot = pid % MAX_SNI;  // overwrite on overflow
    sni_cache[free_slot].set = true;
    sni_cache[free_slot].pid = pid;
    snprintf(sni_cache[free_slot].host, sizeof sni_cache[free_slot].host, "%s", host);
}

static const char *get_sni(int pid) {
    for (int i = 0; i < MAX_SNI; i++)
        if (sni_cache[i].set && sni_cache[i].pid == pid) return sni_cache[i].host;
    return "";
}

// ─── Error helpers ────────────────────────────────────────────────────────────

static void fatalf(const char *f, ...) {
    va_list ap; va_start(ap, f);
    fputs("proc-trace-tls: ", stderr);
    vfprintf(stderr, f, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void fatal(const char *msg) {
    fprintf(stderr, "proc-trace-tls: %s\n", msg);
    exit(1);
}

// ─── libssl discovery ─────────────────────────────────────────────────────────

// resolve_lib resolves a library path to its real path, following all
// symlinks. The kernel's uprobe mechanism does NOT follow symlinks, so we
// must pass the real (non-symlink) path or it attaches to the wrong inode.
static void resolve_lib(const char *path, char *dst, size_t cap) {
    char real[PATH_MAX];
    if (realpath(path, real)) snprintf(dst, cap, "%s", real);
    else                      snprintf(dst, cap, "%s", path);
}

// libFromMaps: scan /proc/<pid>/maps for a libssl mapping.
static bool lib_from_maps(int pid, char *dst, size_t cap) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, "libssl")) continue;
        // fields: addr perms offset dev inode pathname  (6th field, 1-indexed)
        char *save = NULL, *tok = strtok_r(line, " \t\n", &save);
        char *fields[6] = {0};
        int n = 0;
        for (; tok && n < 6; tok = strtok_r(NULL, " \t\n", &save))
            fields[n++] = tok;
        if (n >= 6) {
            struct stat st;
            if (stat(fields[5], &st) == 0) {
                resolve_lib(fields[5], dst, cap);
                fclose(f);
                return true;
            }
        }
    }
    fclose(f);
    return false;
}

static bool find_libssl(char *dst, size_t cap) {
    static const char *candidates[] = {
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib64/libssl.so.3",
        "/lib64/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib/aarch64-linux-gnu/libssl.so.1.1",
    };

    if (watch_n > 0) {
        for (int i = 0; i < watch_n; i++)
            if (lib_from_maps(watch_pids[i], dst, cap)) return true;
    }

    for (int i = 0; i < (int)(sizeof candidates / sizeof candidates[0]); i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0) {
            resolve_lib(candidates[i], dst, cap);
            return true;
        }
    }
    return false;
}

// ─── Remote host resolution ───────────────────────────────────────────────────

// parseHexAddr converts a kernel hex address "AABBCCDD:PPPP" (IPv4
// little-endian) or the 16-byte IPv6 form into "ip:port".
static bool parse_hex_addr(const char *hex_addr, bool is_v6, char *dst, size_t cap) {
    const char *colon = strchr(hex_addr, ':');
    if (!colon) return false;
    char addr_hex[64];
    size_t alen = (size_t)(colon - hex_addr);
    if (alen >= sizeof addr_hex) return false;
    memcpy(addr_hex, hex_addr, alen);
    addr_hex[alen] = 0;
    const char *port_hex = colon + 1;

    char *e;
    unsigned long port_n = strtoul(port_hex, &e, 16);
    if (e == port_hex || port_n > 0xFFFF) return false;
    int port = (int)port_n;
    if (port == 0) return false;

    // hex.DecodeString requires an even-length, all-hex string.
    size_t hl = strlen(addr_hex);
    if (hl % 2 != 0) return false;
    unsigned char b[16];
    size_t bn = hl / 2;
    if (bn > sizeof b) return false;
    for (size_t i = 0; i < bn; i++) {
        char pair[3] = { addr_hex[i*2], addr_hex[i*2+1], 0 };
        char *pe;
        unsigned long v = strtoul(pair, &pe, 16);
        if (pe != pair + 2) return false;
        b[i] = (unsigned char)v;
    }

    char ipstr[INET6_ADDRSTRLEN];
    if (!is_v6) {
        if (bn != 4) return false;
        // little-endian uint32 → dotted quad (matches net.IPv4 ordering).
        uint32_t addr32 = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                          ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        struct in_addr in;
        in.s_addr = htonl(((addr32 & 0xFF) << 24) |
                          ((addr32 & 0xFF00) << 8) |
                          ((addr32 >> 8) & 0xFF00) |
                          ((addr32 >> 24) & 0xFF));
        // loopback / unspecified check on the resulting IPv4.
        uint8_t o0 = (uint8_t)(addr32),       o1 = (uint8_t)(addr32 >> 8);
        uint8_t o2 = (uint8_t)(addr32 >> 16), o3 = (uint8_t)(addr32 >> 24);
        if (o0 == 127) return false;                       // loopback
        if (o0 == 0 && o1 == 0 && o2 == 0 && o3 == 0) return false; // unspecified
        if (!inet_ntop(AF_INET, &in, ipstr, sizeof ipstr)) return false;
    } else {
        if (bn != 16) return false;
        // reverse each 4-byte group
        for (int i = 0; i < 16; i += 4) {
            unsigned char t;
            t = b[i];   b[i]   = b[i+3]; b[i+3] = t;
            t = b[i+1]; b[i+1] = b[i+2]; b[i+2] = t;
        }
        struct in6_addr in6;
        memcpy(&in6, b, 16);
        // skip loopback / link-local
        if (IN6_IS_ADDR_LOOPBACK(&in6) || IN6_IS_ADDR_LINKLOCAL(&in6)) return false;
        if (IN6_IS_ADDR_LOOPBACK(&in6) || IN6_IS_ADDR_UNSPECIFIED(&in6)) return false;
        if (!inet_ntop(AF_INET6, &in6, ipstr, sizeof ipstr)) return false;
    }

    if (!no_reverse_dns) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = is_v6 ? AF_INET6 : AF_INET;
        hints.ai_flags = AI_NUMERICHOST;
        if (getaddrinfo(ipstr, NULL, &hints, &res) == 0 && res) {
            char hbuf[NI_MAXHOST];
            if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof hbuf,
                            NULL, 0, NI_NAMEREQD) == 0) {
                // strip a single trailing dot, mirror "%s:%d"
                size_t L = strlen(hbuf);
                if (L && hbuf[L-1] == '.') hbuf[L-1] = 0;
                snprintf(dst, cap, "%s:%d", hbuf, port);
                freeaddrinfo(res);
                return true;
            }
            freeaddrinfo(res);
        }
    }
    snprintf(dst, cap, "%s:%d", ipstr, port);
    return true;
}

// remoteFromProcNet reads /proc/<pid>/net/tcp[6], returns "IP:port" of the
// first ESTABLISHED (state=01) connection. Empty on failure.
static bool remote_from_proc_net(int pid, char *dst, size_t cap) {
    const char *protos[] = { "tcp6", "tcp" };
    for (int pi = 0; pi < 2; pi++) {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/net/%s", pid, protos[pi]);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[1024];
        bool first = true;
        while (fgets(line, sizeof line, f)) {
            if (first) { first = false; continue; }   // skip header
            char *save = NULL, *tok = strtok_r(line, " \t\n", &save);
            char *fields[4] = {0};
            int n = 0;
            for (; tok && n < 4; tok = strtok_r(NULL, " \t\n", &save))
                fields[n++] = tok;
            if (n < 4) continue;
            if (strcmp(fields[3], "01") != 0) continue;   // 01 = ESTABLISHED
            if (parse_hex_addr(fields[2], strcmp(protos[pi], "tcp6") == 0,
                               dst, cap)) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    return false;
}

// remoteHost returns SNI (preferred) or IP:port from /proc/net/tcp[6].
static void remote_host(int pid, char *dst, size_t cap) {
    const char *sni = get_sni(pid);
    if (sni && *sni) { snprintf(dst, cap, "%s", sni); return; }
    if (!remote_from_proc_net(pid, dst, cap)) dst[0] = 0;
}

// ─── Symbol offset ────────────────────────────────────────────────────────────

// mustLookPath: first existing dir/name, else "/usr/bin/<name>".
static void must_look_path(const char *name, char *dst, size_t cap) {
    static const char *dirs[] = {
        "/usr/bin", "/bin", "/usr/local/bin", "/sbin", "/usr/sbin"
    };
    for (int i = 0; i < (int)(sizeof dirs / sizeof dirs[0]); i++) {
        char p[PATH_MAX];
        snprintf(p, sizeof p, "%s/%s", dirs[i], name);
        struct stat st;
        if (stat(p, &st) == 0) { snprintf(dst, cap, "%s", p); return; }
    }
    snprintf(dst, cap, "/usr/bin/%s", name);
}

// runCmd: fork/exec name with args, capture stdout+stderr. Returns malloc'd
// buffer (caller frees) and sets *out_len. NULL on exec failure.
static char *run_cmd(const char *name, char *const argv[], size_t *out_len) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return NULL;

    char prog[PATH_MAX];
    must_look_path(name, prog, sizeof prog);

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return NULL; }
    if (pid == 0) {
        // child: stdin from /dev/null-ish parent stdin, stdout+stderr → pipe
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(prog, argv);
        _exit(127);
    }
    close(pipefd[1]);

    char  *buf = NULL;
    size_t len = 0, capacity = 0;
    char   tmp[4096];
    for (;;) {
        ssize_t r = read(pipefd[0], tmp, sizeof tmp);
        if (r <= 0) break;
        if (len + (size_t)r + 1 > capacity) {
            capacity = (len + (size_t)r + 1) * 2;
            char *nb = realloc(buf, capacity);
            if (!nb) { free(buf); close(pipefd[0]); return NULL; }
            buf = nb;
        }
        memcpy(buf + len, tmp, (size_t)r);
        len += (size_t)r;
    }
    close(pipefd[0]);
    int ws;
    waitpid(pid, &ws, 0);

    if (!buf) { buf = malloc(1); if (buf) buf[0] = 0; }
    else      buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}

// symbolOffset: parse `nm -D --defined-only <lib>`, fall back to
// `objdump -T <lib>`. Returns true and sets *off on success.
//
// Go used two regexes:
//   ^([0-9a-f]+)\s+(?:[0-9a-f]+\s+)?\S+\s+SYM\b
//   ^([0-9a-f]+)\s+\S\s+SYM\b
static bool sym_match(const char *data, const char *sym, uint64_t *off) {
    char pat1[512], pat2[512];
    // \b after the (escaped-free, alnum/underscore) symbol → require a
    // non-[[:alnum:]_] boundary (or end). regcomp lacks \b, so emulate with
    // a trailing alternation.
    snprintf(pat1, sizeof pat1,
             "^([0-9a-f]+)[[:space:]]+([0-9a-f]+[[:space:]]+)?"
             "[^[:space:]]+[[:space:]]+%s([^[:alnum:]_]|$)", sym);
    snprintf(pat2, sizeof pat2,
             "^([0-9a-f]+)[[:space:]]+[^[:space:]][[:space:]]+%s([^[:alnum:]_]|$)",
             sym);
    // NOTE: deviation from Go. Go's two regexes assume the `nm -D
    // --defined-only` 3-column layout. On distros where `nm -D` is empty
    // (e.g. RHEL/Fedora libssl) we fall back to `objdump -T`, whose layout
    // is `addr g DF .text size VER name` — six tokens the Go patterns
    // never match (the Go tool is silently broken there). pat3 is a
    // generic "hex addr … <sym> at end-of-line" matcher; the *UND* /
    // zero-offset guard below rejects undefined-symbol rows.
    char pat3[512];
    snprintf(pat3, sizeof pat3,
             "^([0-9a-f]+)[[:space:]]+.*[^[:alnum:]_]%s$", sym);

    const char *pats[3] = { pat1, pat2, pat3 };
    for (int p = 0; p < 3; p++) {
        regex_t re;
        if (regcomp(&re, pats[p], REG_EXTENDED | REG_NEWLINE) != 0) continue;
        regmatch_t m[2];
        // Match line-by-line so REG_NEWLINE '^' anchors correctly.
        const char *line = data;
        bool found = false;
        while (*line) {
            const char *nl = strchr(line, '\n');
            size_t llen = nl ? (size_t)(nl - line) : strlen(line);
            char lbuf[1024];
            if (llen >= sizeof lbuf) llen = sizeof lbuf - 1;
            memcpy(lbuf, line, llen);
            lbuf[llen] = 0;
            if (regexec(&re, lbuf, 2, m, 0) == 0 && m[1].rm_so >= 0 &&
                !strstr(lbuf, "*UND*")) {              // skip undefined syms
                char hexbuf[32];
                int hl = m[1].rm_eo - m[1].rm_so;
                if (hl > 0 && hl < (int)sizeof hexbuf) {
                    memcpy(hexbuf, lbuf + m[1].rm_so, (size_t)hl);
                    hexbuf[hl] = 0;
                    uint64_t v = strtoull(hexbuf, NULL, 16);
                    if (v != 0) { *off = v; found = true; }   // 0 == UND/abs
                }
            }
            if (found) break;
            if (!nl) break;
            line = nl + 1;
        }
        regfree(&re);
        if (found) return true;
    }
    return false;
}

static bool symbol_offset(const char *lib_path, const char *sym, uint64_t *off) {
    char *data;
    size_t len;

    char *nm_argv[]  = { "nm", "-D", "--defined-only", (char *)lib_path, NULL };
    data = run_cmd("nm", nm_argv, &len);
    if (!data || len == 0) {
        free(data);
        char *od_argv[] = { "objdump", "-T", (char *)lib_path, NULL };
        data = run_cmd("objdump", od_argv, &len);
        if (!data) return false;
    }

    bool ok = sym_match(data, sym, off);
    free(data);
    return ok;
}

// ─── Uprobe management ────────────────────────────────────────────────────────

typedef struct {
    char name[128];
    bool is_ret;
    char dir[8];
    char symbol[64];
} probe_entry;

#define MAX_PROBES 32
static probe_entry registered[MAX_PROBES];
static int         registered_n;

// appendToFile / write_str use raw open()+write() (no stdio buffering),
// mirroring Go's os.OpenFile + os.File.Write. tracefs control files
// (uprobe_events, .../enable) must receive each command as one unbuffered
// write() at the syscall boundary; routing them through buffered stdio
// makes glibc swallow the kernel's write error (and on some kernels emit
// no write() at all), so the real EINVAL/ENOENT was never surfaced.
static int append_to_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) return -1;
    char buf[1024];
    int len = snprintf(buf, sizeof buf, "%s\n", content);
    if (len < 0 || (size_t)len >= sizeof buf) { close(fd); return -1; }
    ssize_t w = write(fd, buf, (size_t)len);
    int e = errno;
    close(fd);
    if (w != len) { errno = e; return -1; }
    return 0;
}

static int write_str(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return -1;
    ssize_t w = write(fd, s, strlen(s));
    int e = errno;
    close(fd);
    if (w != (ssize_t)strlen(s)) { errno = e; return -1; }
    return 0;
}

static int register_uprobes(const char *lib_path) {
    // dedupe set of probe names
    char seen[NTARGETS][128];
    int  seen_n = 0;

    for (int ti = 0; ti < NTARGETS; ti++) {
        uint64_t offset;
        if (!symbol_offset(lib_path, probe_targets[ti].symbol, &offset)) {
            if (verbose)
                fprintf(stderr, "  skipping %s: symbol %s not found in %s\n",
                        probe_targets[ti].symbol, probe_targets[ti].symbol,
                        lib_path);
            continue;
        }

        const char *prefix = probe_targets[ti].is_ret ? "r" : "p";
        char name[128];
        snprintf(name, sizeof name, "tls_%s_%s",
                 probe_targets[ti].dir, probe_targets[ti].symbol);
        if (probe_targets[ti].is_ret)
            strncat(name, "_ret", sizeof name - strlen(name) - 1);

        bool dup = false;
        for (int s = 0; s < seen_n; s++)
            if (!strcmp(seen[s], name)) { dup = true; break; }
        if (dup) continue;
        snprintf(seen[seen_n++], 128, "%s", name);

        // Remove any stale probe with this name (previous run killed without
        // cleanup). Disable before removing; use the full group/name format.
        char enable_path[256];
        snprintf(enable_path, sizeof enable_path,
                 "%s/events/uprobes/%s/enable", TRACING_BASE, name);
        (void)write_str(enable_path, "0");
        char rm[160];
        snprintf(rm, sizeof rm, "-:uprobes/%s", name);
        (void)append_to_file(UPROBE_EVENTS, rm);

        char line[512];
        snprintf(line, sizeof line, "%s:%s %s:0x%llx",
                 prefix, name, lib_path, (unsigned long long)offset);
        if (probe_targets[ti].extra_args[0]) {
            strncat(line, " ", sizeof line - strlen(line) - 1);
            strncat(line, probe_targets[ti].extra_args,
                    sizeof line - strlen(line) - 1);
        }
        if (append_to_file(UPROBE_EVENTS, line) != 0) {
            if (verbose)
                fprintf(stderr, "  uprobe %s: %s\n", name, strerror(errno));
            continue;
        }

        if (verbose)
            fprintf(stderr, "  registered: %s @ 0x%llx\n",
                    name, (unsigned long long)offset);

        snprintf(enable_path, sizeof enable_path,
                 "%s/events/uprobes/%s/enable", TRACING_BASE, name);
        if (write_str(enable_path, "1") != 0 && verbose)
            fprintf(stderr, "  enable %s: %s\n", name, strerror(errno));

        if (probe_targets[ti].filter[0]) {
            char filter_path[256];
            snprintf(filter_path, sizeof filter_path,
                     "%s/events/uprobes/%s/filter", TRACING_BASE, name);
            if (write_str(filter_path, probe_targets[ti].filter) != 0 && verbose)
                fprintf(stderr, "  filter %s: %s\n", name, strerror(errno));
        }

        if (registered_n < MAX_PROBES) {
            probe_entry *pe = &registered[registered_n++];
            snprintf(pe->name, sizeof pe->name, "%s", name);
            pe->is_ret = probe_targets[ti].is_ret;
            snprintf(pe->dir, sizeof pe->dir, "%s", probe_targets[ti].dir);
            snprintf(pe->symbol, sizeof pe->symbol, "%s",
                     probe_targets[ti].symbol);
        }
    }

    if (registered_n == 0) return -1;
    return 0;
}

static void cleanup_uprobes(void) {
    for (int i = 0; i < registered_n; i++) {
        char enable_path[256];
        snprintf(enable_path, sizeof enable_path,
                 "%s/events/uprobes/%s/enable", TRACING_BASE,
                 registered[i].name);
        (void)write_str(enable_path, "0");
        char rm[160];
        snprintf(rm, sizeof rm, "-:uprobes/%s", registered[i].name);
        (void)append_to_file(UPROBE_EVENTS, rm);
    }
}

// ─── Trace event parsing ──────────────────────────────────────────────────────
//
// Go regexes (translated to POSIX ERE):
//   traceRe: ^\s*(\S+)-(\d+)\s+(?:\(\S+\)\s+)?\[\d+\].*\s+([\d.]+):\s+(tls_\w+)
//   sniRe:   (?:arg1|sni)="([^"]*)"
// POSIX has no non-capturing groups, so sniRe's wanted text shifts from
// group 1 to group 2.

static regex_t trace_re, sni_re;

static void compile_regexes(void) {
    const char *tr =
        "^[[:space:]]*([^[:space:]]+)-([0-9]+)[[:space:]]+"
        "(\\([^[:space:]]+\\)[[:space:]]+)?"
        "\\[[0-9]+\\].*[[:space:]]+([0-9.]+):[[:space:]]+(tls_[[:alnum:]_]+)";
    const char *sr = "(arg1|sni)=\"([^\"]*)\"";
    if (regcomp(&trace_re, tr, REG_EXTENDED) != 0)
        fatal("internal: failed to compile trace regex");
    if (regcomp(&sni_re, sr, REG_EXTENDED) != 0)
        fatal("internal: failed to compile sni regex");
}

typedef struct {
    char   comm[256];
    int    pid;
    double ts;
    char   probe_name[64];
    char   dir[8];
    char   sni[256];   // non-empty only for dir=="sni"
} tls_event;

static bool parse_line(const char *line, tls_event *ev) {
    regmatch_t m[6];
    if (regexec(&trace_re, line, 6, m, 0) != 0) return false;

    memset(ev, 0, sizeof *ev);

    // group 1: comm
    int L = m[1].rm_eo - m[1].rm_so;
    if (L > (int)sizeof ev->comm - 1) L = (int)sizeof ev->comm - 1;
    memcpy(ev->comm, line + m[1].rm_so, (size_t)L);
    ev->comm[L] = 0;

    // group 2: pid
    char numbuf[32];
    L = m[2].rm_eo - m[2].rm_so;
    if (L > (int)sizeof numbuf - 1) L = (int)sizeof numbuf - 1;
    memcpy(numbuf, line + m[2].rm_so, (size_t)L);
    numbuf[L] = 0;
    ev->pid = atoi(numbuf);

    // group 4: timestamp
    L = m[4].rm_eo - m[4].rm_so;
    if (L > (int)sizeof numbuf - 1) L = (int)sizeof numbuf - 1;
    memcpy(numbuf, line + m[4].rm_so, (size_t)L);
    numbuf[L] = 0;
    ev->ts = strtod(numbuf, NULL);

    // group 5: probe name
    L = m[5].rm_eo - m[5].rm_so;
    if (L > (int)sizeof ev->probe_name - 1) L = (int)sizeof ev->probe_name - 1;
    memcpy(ev->probe_name, line + m[5].rm_so, (size_t)L);
    ev->probe_name[L] = 0;

    if (strstr(ev->probe_name, "_sni")) {
        snprintf(ev->dir, sizeof ev->dir, "sni");
        regmatch_t sm[3];
        if (regexec(&sni_re, line, 3, sm, 0) == 0 && sm[2].rm_so >= 0) {
            int sl = sm[2].rm_eo - sm[2].rm_so;
            if (sl > (int)sizeof ev->sni - 1) sl = (int)sizeof ev->sni - 1;
            memcpy(ev->sni, line + sm[2].rm_so, (size_t)sl);
            ev->sni[sl] = 0;
        }
    } else if (strstr(ev->probe_name, "_read")) {
        snprintf(ev->dir, sizeof ev->dir, "read");
    } else if (strstr(ev->probe_name, "_write")) {
        snprintf(ev->dir, sizeof ev->dir, "write");
    } else {
        snprintf(ev->dir, sizeof ev->dir, "?");
    }
    return true;
}

static bool is_watched(int pid) {
    if (watch_n == 0) return true;
    for (int i = 0; i < watch_n; i++) if (watch_pids[i] == pid) return true;
    return false;
}

// ─── Event output ─────────────────────────────────────────────────────────────

static long long counter;

#define MAX_CONN 4096
static struct { char key[320]; bool set; } conn_seen[MAX_CONN];

static bool conn_mark(const char *key) {
    unsigned h = 5381;
    for (const char *p = key; *p; p++) h = h * 33u + (unsigned char)*p;
    int start = (int)(h % MAX_CONN);
    for (int i = 0; i < MAX_CONN; i++) {
        int idx = (start + i) % MAX_CONN;
        if (!conn_seen[idx].set) {
            conn_seen[idx].set = true;
            snprintf(conn_seen[idx].key, sizeof conn_seen[idx].key, "%s", key);
            return false;   // newly inserted
        }
        if (!strcmp(conn_seen[idx].key, key)) return true;  // already seen
    }
    return false;  // table full — treat as new (best effort)
}

static const char *str_trim_prefix(const char *s, const char *pfx) {
    size_t n = strlen(pfx);
    return strncmp(s, pfx, n) == 0 ? s + n : s;
}

static void print_event(const tls_event *ev) {
    // SNI events update the per-PID cache and are otherwise silent.
    if (!strcmp(ev->dir, "sni")) {
        if (ev->sni[0]) set_sni(ev->pid, ev->sni);
        return;
    }

    char host[300];
    remote_host(ev->pid, host, sizeof host);

    // One line per (pid, host) — suppress duplicate read/write events.
    char key[320];
    snprintf(key, sizeof key, "%d|%s", ev->pid, host);
    if (conn_mark(key)) return;

    counter++;

    // Go: time.Unix(0, int64(ev.ts*1e9)).Format("15:04:05.000")
    double tsf = ev->ts * 1e9;
    long long nanos = (long long)tsf;
    time_t sec = (time_t)(nanos / 1000000000LL);
    long long frac_ns = nanos % 1000000000LL;
    if (frac_ns < 0) { frac_ns += 1000000000LL; sec -= 1; }
    int msec = (int)(frac_ns / 1000000LL);
    struct tm tm;
    localtime_r(&sec, &tm);
    char ts[16];
    snprintf(ts, sizeof ts, "%02d:%02d:%02d.%03d",
             tm.tm_hour, tm.tm_min, tm.tm_sec, msec);

    const char *dir_str, *dir_clr;
    if (!strcmp(ev->dir, "write")) { dir_str = "TX"; dir_clr = "33"; }
    else                           { dir_str = "RX"; dir_clr = "36"; }

    // sym = probeName with tls_read_/tls_write_ prefix and _ret suffix stripped
    char sym[64];
    const char *p = ev->probe_name;
    p = str_trim_prefix(p, "tls_read_");
    p = str_trim_prefix(p, "tls_write_");
    snprintf(sym, sizeof sym, "%s", p);
    size_t sl = strlen(sym);
    if (sl >= 4 && !strcmp(sym + sl - 4, "_ret")) sym[sl - 4] = 0;

    char pidbuf[16];
    snprintf(pidbuf, sizeof pidbuf, "%d", ev->pid);

    const char *pid_s  = clr(color_mode, "33", pidbuf);
    const char *comm_s = clr(color_mode, "96", ev->comm);
    const char *dir_f  = clr(color_mode, dir_clr, dir_str);
    const char *ts_s   = clr(color_mode, "2", ts);
    const char *sym_s  = clr(color_mode, "2", sym);

    char host_s[512] = "";
    if (host[0])
        snprintf(host_s, sizeof host_s, "  %s", clr(color_mode, "35", host));

    fprintf(out, "%s %s %s %s %s%s\n",
            ts_s, pid_s, comm_s, dir_f, sym_s, host_s);
    fflush(out);
}

// ─── Signal-driven cleanup ────────────────────────────────────────────────────

static void on_sig(int s) {
    (void)s;
    if (!quiet_mode)
        fprintf(stderr, "\n\ncaptured %lld TLS events\n", counter);
    cleanup_uprobes();
    _exit(0);
}

// ─── Usage ────────────────────────────────────────────────────────────────────

static void usage(void) {
    const char *bold = "\033[1m", *dim = "\033[2m", *reset = "\033[0m";
    const char *cyan = "\033[36m", *yellow = "\033[33m", *green = "\033[32m";
    FILE *e = stderr;
    fprintf(e, "\n  %s%s🔒 proc-trace-tls%s %s%s%s — plaintext TLS traffic interceptor for Linux\n\n",
            bold, cyan, reset, dim, tracep_version, reset);
    fprintf(e, "  %sUsage:%s\n", bold, reset);
    fprintf(e, "    proc-trace-tls %s[flags]%s\n\n", dim, reset);
    fprintf(e, "  %sFlags:%s\n", bold, reset);
    fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n", yellow, reset, dim, reset);
    fprintf(e, "    🔗  %s-l%s %sLIB%s      path to libssl.so %s(auto-detected if omitted)%s\n", yellow, reset, cyan, reset, dim, reset);
    fprintf(e, "    📝  %s-o%s %sFILE%s     log output to FILE instead of stdout\n", yellow, reset, cyan, reset);
    fprintf(e, "    🎯  %s-p%s %sPID%s      trace only PID(s) %s(comma-separated)%s\n", yellow, reset, cyan, reset, dim, reset);
    fprintf(e, "    🤫  %s-q%s          suppress startup messages\n", yellow, reset);
    fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset);
    fprintf(e, "    🚫  %s-R%s          skip reverse DNS %s(show raw IPs)%s\n", yellow, reset, dim, reset);
    fprintf(e, "    📊  %s-s%s          event summary only\n", yellow, reset);
    fprintf(e, "    🔍  %s-v%s          verbose probe registration\n", yellow, reset);
    fprintf(e, "\n  %sExamples:%s\n", bold, reset);
    fprintf(e, "    sudo proc-trace-tls\n\n");
    fprintf(e, "    sudo proc-trace-tls %s-p%s $(pgrep curl)\n\n", green, reset);
    fprintf(e, "    sudo proc-trace-tls %s-R%s  %s# raw IPs, no DNS%s\n\n", green, reset, dim, reset);
    exit(1);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int tls_main(int argc, char **argv) {
    out = stdout;

    // argv[0] is "tracep tls". Parse flags like tls.go Main(): args = os.Args[1:].
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strlen(a) < 2 || a[0] != '-')
            fatalf("unexpected argument: %s", a);
        for (const char *ch = a + 1; *ch; ch++) {
            switch (*ch) {
            case 'c':
                color_force = true;
                break;
            case 'h':
                usage();
                break;
            case 'l':
                if (i + 1 >= argc) fatal("-l requires a path");
                i++;
                snprintf(libssl_path, sizeof libssl_path, "%s", argv[i]);
                break;
            case 'o':
                if (i + 1 >= argc) fatal("-o requires a path");
                i++;
                snprintf(out_file, sizeof out_file, "%s", argv[i]);
                break;
            case 'p': {
                if (i + 1 >= argc) fatal("-p requires a PID list");
                i++;
                char *dup = strdup(argv[i]), *save = NULL;
                for (char *t = strtok_r(dup, ",", &save); t;
                     t = strtok_r(NULL, ",", &save)) {
                    while (*t == ' ' || *t == '\t') t++;
                    size_t Ln = strlen(t);
                    while (Ln && (t[Ln-1] == ' ' || t[Ln-1] == '\t'))
                        t[--Ln] = 0;
                    if (!*t) continue;
                    char *e;
                    long pid = strtol(t, &e, 10);
                    if (*e != 0 || pid <= 0)
                        fatalf("-p: invalid PID: %s", t);
                    if (watch_n < MAX_PIDS) watch_pids[watch_n++] = (int)pid;
                }
                free(dup);
                break;
            }
            case 'q':
                quiet_mode = true;
                break;
            case 'Q':
                show_errors = false;
                break;
            case 'R':
                no_reverse_dns = true;
                break;
            case 's':
                size_only = true;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                fatalf("unknown flag -%c", *ch);
            }
        }
    }
    (void)show_errors; (void)size_only;  // parity with Go (parsed, unused)

    if (out_file[0]) {
        out = fopen(out_file, "a");
        if (!out) fatalf("open %s: %s", out_file, strerror(errno));
    }

    if (color_force) {
        color_mode = true;
    } else if (getenv("NO_COLOR") == NULL) {
        color_mode = is_terminal(out);
    }

    if (libssl_path[0] == 0) {
        if (!find_libssl(libssl_path, sizeof libssl_path))
            fatalf("libssl.so not found; use -l to specify\n"
                   "Hint: install openssl or use -l /path/to/libssl.so");
    }

    if (!quiet_mode) {
        fprintf(stderr, "%s\n",
                clr(color_mode, "96", "proc-trace-tls " TRACEP_VERSION));
        fprintf(stderr, "  lib : %s\n", clr(color_mode, "2", libssl_path));
        if (watch_n > 0) {
            char pids[1024] = "";
            for (int i = 0; i < watch_n; i++) {
                char b[16];
                snprintf(b, sizeof b, "%s%d", i ? "," : "", watch_pids[i]);
                strncat(pids, b, sizeof pids - strlen(pids) - 1);
            }
            fprintf(stderr, "  pids: %s\n", clr(color_mode, "33", pids));
        } else {
            fprintf(stderr, "  pids: %s\n", clr(color_mode, "2", "all"));
        }
        fprintf(stderr, "\n");
    }

    if (write_str(TRACE_ON, "1") != 0)
        fatalf("enable tracing: %s\n"
               "Are you root? Is debugfs mounted at %s?",
               strerror(errno), TRACING_BASE);

    // Switch to the no-op tracer so the ring buffer isn't flooded with
    // function-tracer events that would drown out or drop uprobe hits.
    if (write_str(CURRENT_TRACER, "nop") != 0 && verbose)
        fprintf(stderr, "  warning: could not set current_tracer to nop: %s\n",
                strerror(errno));

    compile_regexes();

    if (verbose)
        fprintf(stderr, "Registering uprobes on %s...\n", libssl_path);
    if (register_uprobes(libssl_path) != 0)
        fatalf("no uprobes registered — is OpenSSL installed?");
    if (!quiet_mode)
        fprintf(stderr, "Watching %d probe(s). Press Ctrl-C to stop.\n\n",
                registered_n);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    FILE *f = fopen(TRACE_PIPE, "r");
    if (!f) {
        cleanup_uprobes();
        fatalf("open trace_pipe: %s", strerror(errno));
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) != -1) {
        if (n > 0 && line[n-1] == '\n') line[n-1] = 0;
        tls_event ev;
        if (!parse_line(line, &ev)) continue;
        if (!is_watched(ev.pid)) continue;
        print_event(&ev);
    }
    free(line);
    fclose(f);
    return 0;
}

#else  // !__linux__

int tls_main(int argc, char **argv) {
    (void)argc; (void)argv;
#if defined(__APPLE__)
    const char *os = "darwin";
#else
    const char *os = "unknown";
#endif
    fprintf(stderr,
            "tracep tls: TLS tracing is only supported on Linux (this is %s).\n"
            "Only `tracep ca` and `tracep dns` run on %s.\n",
            os, os);
    return 1;
}

#endif  // __linux__
