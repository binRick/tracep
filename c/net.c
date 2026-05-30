// net — trace network connections system-wide via Linux conntrack netlink
// (port of internal/nettrace/net.go + net_other.go).
//
// Linux only: relies on NETLINK_NETFILTER conntrack multicast + /proc.
// Off Linux this prints the same two-line message as net_other.go.
//
// Threads: reverse-DNS lookups (-r) run on detached background pthreads,
// exactly like net.go's `go func()`. The connDB map, the DNS cache and the
// local-IP set are guarded by mutexes. The integrator must link -lpthread.
#define _GNU_SOURCE
#include "common.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ─── macOS polling backend (mirror of net_darwin.go) ────────────────────────
#if defined(__APPLE__)
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

static int32_t  net_watchPIDs[256];
static int      net_nWatchPIDs;
static bool     net_colorMode, net_colorForce, net_showUser;
static bool     net_showErrors  = true;
static FILE    *net_out;
static int      net_pollIntervalMs = 1000;

// Open-addressing hash of "seen this connection" keys. Capacity is a
// power of two; ~10k connections is plenty for a developer-laptop view.
typedef struct {
    bool     used;
    uint32_t hash;
    int      pid;
    char     proto[8];   // "TCP" / "UDP"
    char     src[64];
    int      sport;
    char     dst[64];
    int      dport;
} net_seen_ent;
#define NETSEEN_CAP 16384
static net_seen_ent net_seen[NETSEEN_CAP];

static uint32_t net_hash(const char *proto, int pid, const char *src, int sport,
                         const char *dst, int dport) {
    uint64_t h = 1469598103934665603ULL; // FNV-64 offset basis
    for (const char *p = proto; *p; p++) { h ^= (uint8_t)*p; h *= 1099511628211ULL; }
    h ^= (uint64_t)(uint32_t)pid; h *= 1099511628211ULL;
    for (const char *p = src; *p; p++) { h ^= (uint8_t)*p; h *= 1099511628211ULL; }
    h ^= (uint64_t)(uint32_t)sport; h *= 1099511628211ULL;
    for (const char *p = dst; *p; p++) { h ^= (uint8_t)*p; h *= 1099511628211ULL; }
    h ^= (uint64_t)(uint32_t)dport; h *= 1099511628211ULL;
    return (uint32_t)h;
}

// Returns true if already seen; otherwise inserts and returns false.
static bool net_seen_check_insert(uint32_t hash, int pid, const char *proto,
                                  const char *src, int sport,
                                  const char *dst, int dport) {
    unsigned i = hash & (NETSEEN_CAP - 1);
    for (unsigned probe = 0; probe < NETSEEN_CAP; probe++) {
        net_seen_ent *e = &net_seen[(i + probe) & (NETSEEN_CAP - 1)];
        if (!e->used) {
            e->used = true;
            e->hash = hash;
            e->pid  = pid;
            snprintf(e->proto, sizeof e->proto, "%s", proto);
            snprintf(e->src,   sizeof e->src,   "%s", src);
            e->sport = sport;
            snprintf(e->dst,   sizeof e->dst,   "%s", dst);
            e->dport = dport;
            return false;
        }
        if (e->hash == hash && e->pid == pid && e->sport == sport && e->dport == dport
            && !strcmp(e->proto, proto) && !strcmp(e->src, src) && !strcmp(e->dst, dst))
            return true;
    }
    return true; // table full — pretend seen
}

static const char *net_c(const char *code, const char *s) {
    return clr(net_colorMode, code, s);
}

static void net_fatalf(const char *f, ...) {
    fputs("tracep net: ", stderr);
    va_list ap;
    va_start(ap, f);
    vfprintf(stderr, f, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
static void net_fatal(const char *m) {
    fprintf(stderr, "tracep net: %s\n", m);
    exit(1);
}

// split_conn — "src->dst" → (src, dst); listening sockets have no arrow.
static void split_conn(const char *body, char *src, size_t srcsz,
                       char *dst, size_t dstsz) {
    const char *arrow = strstr(body, "->");
    if (arrow) {
        size_t L = (size_t)(arrow - body);
        if (L >= srcsz) L = srcsz - 1;
        memcpy(src, body, L); src[L] = 0;
        snprintf(dst, dstsz, "%s", arrow + 2);
    } else {
        snprintf(src, srcsz, "%s", body);
        dst[0] = 0;
    }
}

// split_host_port — "[::1]:443", "127.0.0.1:80", "*:53", "*:*".
static void split_host_port(const char *s, char *ip, size_t ipsz, int *port) {
    *port = 0;
    ip[0] = 0;
    if (!s || !*s || !strcmp(s, "*:*")) return;
    if (s[0] == '[') {
        const char *end = strstr(s, "]:");
        if (!end) return;
        size_t L = (size_t)(end - s - 1);
        if (L >= ipsz) L = ipsz - 1;
        memcpy(ip, s + 1, L); ip[L] = 0;
        *port = atoi(end + 2);
        return;
    }
    const char *colon = strrchr(s, ':');
    if (!colon) { snprintf(ip, ipsz, "%s", s); return; }
    size_t L = (size_t)(colon - s);
    if (L >= ipsz) L = ipsz - 1;
    memcpy(ip, s, L); ip[L] = 0;
    if (!strcmp(ip, "*")) ip[0] = 0;
    if (colon[1] != '*') *port = atoi(colon + 1);
}

// join_host_port — bracket IPv6 literals so "::1:443" isn't ambiguous.
static void join_host_port(const char *ip, int port, char *out, size_t cap) {
    bool isV6 = strchr(ip, ':') != NULL;
    if (!*ip)     snprintf(out, cap, "*:%d", port);
    else if (isV6) snprintf(out, cap, "[%s]:%d", ip, port);
    else           snprintf(out, cap, "%s:%d", ip, port);
}

// lsof_argv builds the argv for an lsof child. Returns the count.
static int lsof_argv(char **argv, int max) {
    int n = 0;
    if (n + 8 > max) return 0;
    argv[n++] = "/usr/sbin/lsof";
    argv[n++] = "-nP";
    argv[n++] = "-i";
    argv[n++] = "-F";
    argv[n++] = "pcLPnu"; // u = numeric uid, so -u can show the real owner
    if (net_nWatchPIDs > 0) {
        static char pidlist[2048];
        size_t w = 0;
        for (int i = 0; i < net_nWatchPIDs; i++) {
            if (i) pidlist[w++] = ',';
            int r = snprintf(pidlist + w, sizeof pidlist - w, "%d", (int)net_watchPIDs[i]);
            if (r < 0 || w + (size_t)r >= sizeof pidlist) break;
            w += (size_t)r;
        }
        pidlist[w] = 0;
        // -a ANDs the -i (network) and -p (pid) selections. Without it lsof
        // ORs its selection options, so `-i -p PID` lists *every* host socket
        // (the -p is effectively ignored) and the per-PID filter is lost.
        argv[n++] = "-a";
        argv[n++] = "-p";
        argv[n++] = pidlist;
    }
    argv[n] = NULL;
    return n;
}

// net_user_of resolves uid -> username into a static buffer (mirrors the Go
// tracer's userOf), falling back to the numeric uid.
static const char *net_user_of(uint32_t uid) {
    static char buf[64];
    struct passwd *pw = getpwuid((uid_t)uid);
    if (pw && pw->pw_name) { snprintf(buf, sizeof buf, "%s", pw->pw_name); return buf; }
    snprintf(buf, sizeof buf, "%u", uid);
    return buf;
}

// CMD-mode child reaping: mirror the Go reference (cmd.Wait(); os.Exit(0))
// so `tracep net CMD...` exits when the command finishes instead of polling
// forever. The handler reaps and flags; the poll loop checks the flag.
static volatile sig_atomic_t net_child_done;
static pid_t                 net_child_pid;
static void net_on_sigchld(int s) {
    (void)s;
    int st;
    pid_t r;
    while ((r = waitpid(-1, &st, WNOHANG)) > 0)
        if (r == net_child_pid) net_child_done = 1;
}

static void net_emit(int pid, const char *comm, uint32_t uid, const char *proto,
                     const char *src, int sport,
                     const char *dst, int dport) {
    char buf[512];
    fprintf(net_out, "%7d ", pid);
    const char *cm = (comm && *comm) ? comm : "?";
    char trimmed[32];
    if (strlen(cm) > 12) snprintf(trimmed, sizeof trimmed, "%.11s…", cm); // 11 + ellipsis (matches Go)
    else                 snprintf(trimmed, sizeof trimmed, "%-12s", cm);
    fprintf(net_out, "%s", net_c("96", trimmed));
    if (net_showUser) {
        char wrapped[80];
        const char *u = net_user_of(uid);
        snprintf(wrapped, sizeof wrapped, " <%s>", u);
        fprintf(net_out, "%s", net_c(strcmp(u, "root") == 0 ? "91" : "92", wrapped));
    }
    fputc(' ', net_out);
    snprintf(buf, sizeof buf, "%-4s", proto);
    fprintf(net_out, "%s ", net_c("2", buf));
    char srcp[80], dstp[80];
    join_host_port(src, sport, srcp, sizeof srcp);
    join_host_port(dst, dport, dstp, sizeof dstp);
    char col[96];
    snprintf(col, sizeof col, "%-30s", srcp);
    fprintf(net_out, "%s ", net_c("32", col));
    if (!*dst && dport == 0) fprintf(net_out, "%s ", net_c("2", "•"));
    else                     fprintf(net_out, "%s ", net_c("36", "→"));
    snprintf(col, sizeof col, "%-30s", dstp);
    fprintf(net_out, "%s\n", net_c("33", col));
}

// net_scan forks lsof, parses -F pcLPn output, and emits any new connection.
static void net_scan(bool seedOnly) {
    char *argv_lsof[16];
    int nargs = lsof_argv(argv_lsof, 16);
    if (nargs == 0) return;
    int pipefd[2];
    if (pipe(pipefd) < 0) return;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], 1);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 2); close(devnull); }
        execv(argv_lsof[0], argv_lsof);
        _exit(127);
    }
    close(pipefd[1]);
    FILE *r = fdopen(pipefd[0], "r");
    if (!r) { close(pipefd[0]); waitpid(pid, NULL, 0); return; }

    int      cur_pid = 0;
    uint32_t cur_uid = 0;
    char cur_comm[64] = "?";
    char cur_proto[8] = "";
    char line[4096];
    while (fgets(line, sizeof line, r)) {
        size_t L = strlen(line);
        while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        if (L < 2) continue;
        switch (line[0]) {
        case 'p':
            cur_pid = atoi(line + 1);
            cur_proto[0] = 0; // new process — clear stale per-process/fd state
            cur_uid = 0;
            break;
        case 'c':
            snprintf(cur_comm, sizeof cur_comm, "%s", line + 1);
            break;
        case 'u':
            cur_uid = (uint32_t)strtoul(line + 1, NULL, 10);
            break;
        case 'f':
            cur_proto[0] = 0; // new fd — clear so non-network fds are skipped
            break;
        case 'P':
            snprintf(cur_proto, sizeof cur_proto, "%s", line + 1);
            break;
        case 'n': {
            // `-p PID` lsof also lists non-network fds (files, UNIX
            // sockets) — those start with '/'. cur_proto stays empty
            // when there was no preceding `P` line for this fd.
            const char *body = line + 1;
            if (!*body || *body == '/' || !cur_proto[0]) break;
            char src[64], dst[64], sip[64], dip[64];
            int sport, dport;
            split_conn(body, src, sizeof src, dst, sizeof dst);
            split_host_port(src, sip, sizeof sip, &sport);
            split_host_port(dst, dip, sizeof dip, &dport);
            if (sport == 0 && dport == 0) break; // unbound/listening (*:*) — match Go
            uint32_t h = net_hash(cur_proto, cur_pid, sip, sport, dip, dport);
            bool already = net_seen_check_insert(h, cur_pid, cur_proto, sip, sport, dip, dport);
            if (already || seedOnly) break;
            net_emit(cur_pid, cur_comm, cur_uid, cur_proto, sip, sport, dip, dport);
            break;
        }
        }
    }
    fclose(r);
    waitpid(pid, NULL, 0);
}

static void net_usage(void) {
    const char *bold    = "\033[1m";
    const char *dim     = "\033[2m";
    const char *reset   = "\033[0m";
    const char *cyan    = "\033[36m";
    const char *yellow  = "\033[33m";
    const char *green   = "\033[32m";
    const char *magenta = "\033[35m";
    FILE *e = stderr;
    fprintf(e, "\n  %s%s🌐 tracep net%s %s%s%s — network-connection tracer (darwin, polling)\n\n",
            bold, cyan, reset, dim, tracep_version, reset);
    fprintf(e, "  %sUsage:%s\n", bold, reset);
    fprintf(e, "    tracep net %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n",
            dim, reset, yellow, reset);
    fprintf(e, "  %sFlags:%s\n", bold, reset);
    fprintf(e, "    🎨  %s-c%s          colorize output\n", yellow, reset);
    fprintf(e, "    ⏲️   %s-i%s %sMS%s        poll interval in ms %s(default 1000)%s\n", yellow, reset, cyan, reset, dim, reset);
    fprintf(e, "    📝  %s-o%s %sFILE%s      log output to FILE\n", yellow, reset, cyan, reset);
    fprintf(e, "    🎯  %s-p%s %sPID%s       watch only PID's own connections\n", yellow, reset, cyan, reset);
    fprintf(e, "    👤  %s-u%s          print owning user\n", yellow, reset);
    fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset);
    fprintf(e, "    %s-t/-U/-r/-4/-6/-O recognized for Linux compatibility (no-op on darwin)%s\n", dim, reset);
    fprintf(e, "\n  %sNotes:%s\n", bold, reset);
    fprintf(e, "    %sdarwin has no netlink conntrack. This build polls `lsof -nP -i` and%s\n", dim, reset);
    fprintf(e, "    %sdiffs snapshots, so short-lived connections may not be observed.%s\n\n", dim, reset);
    fprintf(e, "  %sExamples:%s\n", bold, reset);
    fprintf(e, "    %s# trace one PID's connections%s\n", dim, reset);
    fprintf(e, "    tracep net %s-c -p%s 1234\n\n", green, reset);
    fprintf(e, "    %s# trace a command's subtree%s\n", dim, reset);
    fprintf(e, "    tracep net %s-c%s curl %shttps://example.com%s\n\n", green, reset, magenta, reset);
    exit(1);
}

int net_main(int argc, char **argv) {
    net_out = stdout;
    // Force line buffering — output is otherwise block-buffered when stdout
    // is a file/pipe, and we'd lose unflushed events on SIGTERM.
    setvbuf(stdout, NULL, _IOLBF, 0);
    char **cmdArgs = NULL;
    int    nCmdArgs = 0;
    const char *outFile = NULL;
    int nargs = argc - 1;
    char **args = argv + 1;

    for (int i = 0; i < nargs; i++) {
        char *a = args[i];
        if (strlen(a) < 2 || a[0] != '-') {
            cmdArgs = &args[i];
            nCmdArgs = nargs - i;
            break;
        }
        for (char *pch = a + 1; *pch; pch++) {
            char ch = *pch;
            switch (ch) {
            case 'c': net_colorForce = true; break;
            case 'u': net_showUser   = true; break;
            case 'Q': net_showErrors = false; break;
            case 't': case 'U': case 'r': case '4': case '6': case 'O':
                break; // Linux-only flags, accepted no-op on darwin
            case 'p': {
                if (i + 1 >= nargs) net_fatal("flag -p requires an argument");
                i++;
                char *dup = strdup(args[i]);
                char *save = NULL;
                for (char *s = strtok_r(dup, ",", &save); s; s = strtok_r(NULL, ",", &save)) {
                    while (*s == ' ' || *s == '\t') s++;
                    if (!*s) continue;
                    char *end;
                    errno = 0;
                    long pid = strtol(s, &end, 10);
                    // Reject trailing junk ("12abc") to match Go's strconv.Atoi;
                    // otherwise it would silently target a truncated wrong PID.
                    if (end == s || *end != 0 || errno != 0 || pid <= 0)
                        net_fatalf("-p: invalid PID: %s", s);
                    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
                        net_fatalf("-p %d: no such process", (int)pid);
                    if (net_nWatchPIDs < (int)(sizeof net_watchPIDs / sizeof net_watchPIDs[0]))
                        net_watchPIDs[net_nWatchPIDs++] = (int32_t)pid;
                }
                free(dup);
                break;
            }
            case 'o':
                if (i + 1 >= nargs) net_fatal("flag -o requires an argument");
                i++;
                outFile = args[i];
                break;
            case 'i': {
                if (i + 1 >= nargs) net_fatal("flag -i requires an argument (poll interval ms)");
                i++;
                long v = strtol(args[i], NULL, 10);
                if (v <= 0) net_fatalf("-i: invalid interval: %s", args[i]);
                net_pollIntervalMs = (int)v;
                break;
            }
            case 'h': net_usage(); break;
            default: net_fatalf("unknown flag -%c", ch);
            }
        }
    }

    if (outFile && *outFile) {
        FILE *f = fopen(outFile, "a");
        if (!f) net_fatalf("open %s: %s", outFile, strerror(errno));
        net_out = f;
        // The setvbuf above line-buffers stdout; a freshly fopen'd file is
        // block-buffered, so without this its low-volume output (e.g. -p PID)
        // would be lost on signal termination (no SIGTERM flush). Mirrors
        // exec_main; net_emit has no per-event fflush like dns.c/tls.c.
        setvbuf(net_out, NULL, _IOLBF, 0);
    }
    if (net_colorForce) net_colorMode = true;
    else if (!getenv("NO_COLOR")) net_colorMode = is_terminal(net_out);

    // CMD mode: run the command and watch its pid.
    if (nCmdArgs > 0) {
        pid_t pid = fork();
        if (pid < 0) net_fatalf("exec %s: %s", cmdArgs[0], strerror(errno));
        if (pid == 0) {
            char **cargv = malloc((size_t)(nCmdArgs + 1) * sizeof *cargv);
            for (int k = 0; k < nCmdArgs; k++) cargv[k] = cmdArgs[k];
            cargv[nCmdArgs] = NULL;
            execvp(cargv[0], cargv);
            fprintf(stderr, "tracep net: exec %s: %s\n", cmdArgs[0], strerror(errno));
            _exit(1);
        }
        if (net_nWatchPIDs < (int)(sizeof net_watchPIDs / sizeof net_watchPIDs[0]))
            net_watchPIDs[net_nWatchPIDs++] = (int32_t)pid;
        // Reap the child and exit when it finishes, mirroring the Go
        // reference (cmd.Wait(); os.Exit(0)). SIG_IGN alone would only
        // auto-reap and the poll loop would otherwise run forever.
        net_child_pid = pid;
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = net_on_sigchld;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGCHLD, &sa, NULL);
    }

    // Seed: mark currently-open sockets as already seen so we only print
    // connections that appear AFTER tracep starts.
    net_scan(true);

    if (net_showErrors) {
        const char *suffix = (geteuid() != 0)
            ? "; non-root sees sockets only for own-user processes"
            : "";
        fprintf(stderr, "tracep net: polling at %dms on darwin — short-lived connections may be missed%s\n",
                net_pollIntervalMs, suffix);
    }

    struct timespec ts = {
        .tv_sec  = net_pollIntervalMs / 1000,
        .tv_nsec = (long)(net_pollIntervalMs % 1000) * 1000000L,
    };
    for (;;) {
        nanosleep(&ts, NULL);
        net_scan(false);
        // CMD mode: once the launched command has exited, do a final scan
        // to catch its last connections, then exit like the Go reference.
        if (net_child_done) { net_scan(false); exit(0); }
    }
}

#elif !defined(__linux__) // ── non-Linux, non-darwin stub ──────────────────────

int net_main(int argc, char **argv) {
    (void)argc;
    (void)argv;
#if defined(__FreeBSD__)
    const char *os = "freebsd";
#elif defined(__OpenBSD__)
    const char *os = "openbsd";
#elif defined(__NetBSD__)
    const char *os = "netbsd";
#else
    const char *os = "this platform";
#endif
    fprintf(stderr,
            "tracep net: network-connection tracing is only supported on Linux and macOS (this is %s).\n"
            "Only `tracep ca` and `tracep dns` run on %s.\n",
            os, os);
    return 1;
}

#else // __linux__

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

// ─── Netfilter / conntrack constants ──────────────────────────────────────────

#define NETLINK_NETFILTER_ 12

#define NF_CT_NEW     1u // bit 0 — new connections
#define NF_CT_UPDATE  2u // bit 1 — TCP state changes
#define NF_CT_DESTROY 4u // bit 2 — closed connections

#define NFNL_SUBSYS_CTNETLINK 1

#define MSG_CT_NEW    ((NFNL_SUBSYS_CTNETLINK << 8) | 0) // 256
#define MSG_CT_DELETE ((NFNL_SUBSYS_CTNETLINK << 8) | 2) // 258

#define NFGEN_MSG_SIZE 4 // sizeof(struct nfgenmsg)

#define NLA_F_NESTED_         0x8000
#define NLA_F_NET_BYTEORDER_  0x4000

#define CTA_TUPLE_ORIG_ 1
#define CTA_PROTOINFO_  4

#define CTA_TUPLE_IP_    1
#define CTA_TUPLE_PROTO_ 2

#define CTA_IPV4_SRC_ 1
#define CTA_IPV4_DST_ 2
#define CTA_IPV6_SRC_ 3
#define CTA_IPV6_DST_ 4

#define CTA_PROTO_NUM_      1
#define CTA_PROTO_SRC_PORT_ 2
#define CTA_PROTO_DST_PORT_ 3

#define CTA_PROTOINFO_TCP_       1
#define CTA_PROTOINFO_TCP_STATE_ 1

#define NLM_F_CREATE_ 0x400

// conntrack TCP state names (enum tcp_conntrack in kernel)
static const char *tcp_state_names[12] = {
    "NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED",
    "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT",
    "CLOSE", "LISTEN", "MAX", "IGNORE",
};

static const char *tcp_state_name(uint8_t s) {
    if ((int)s < 12) return tcp_state_names[s];
    static char b[16];
    snprintf(b, sizeof b, "STATE%u", s);
    return b;
}

// ─── Connection tuple ─────────────────────────────────────────────────────────

typedef struct {
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    int      src_len;   // 4 or 16; 0 = unset
    int      dst_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} conn_tuple;

// ipStr renders an IP exactly like Go's net.IP.String(): dotted-quad for v4,
// RFC 5952 canonical (lowercase, "::" run-compression) for v6 — which is what
// inet_ntop(AF_INET6) produces.
static void ip_str(const uint8_t *ip, int len, char *out, size_t cap) {
    if (len == 4) {
        inet_ntop(AF_INET, ip, out, (socklen_t)cap);
    } else if (len == 16) {
        inet_ntop(AF_INET6, ip, out, (socklen_t)cap);
    } else {
        snprintf(out, cap, "?");
    }
}

static void tuple_key(const conn_tuple *t, char *out, size_t cap) {
    char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
    ip_str(t->src_ip, t->src_len, s, sizeof s);
    ip_str(t->dst_ip, t->dst_len, d, sizeof d);
    snprintf(out, cap, "%s:%d|%s:%d|%d",
             s, t->src_port, d, t->dst_port, t->proto);
}

static const char *proto_str(uint8_t proto) {
    switch (proto) {
    case 6:  return "TCP";
    case 17: return "UDP";
    case 1:  return "ICMP";
    default: {
        static char b[16];
        snprintf(b, sizeof b, "IP%u", proto);
        return b;
    }
    }
}

// ─── Connection direction ─────────────────────────────────────────────────────

typedef enum {
    DIR_UNKNOWN  = 0,
    DIR_OUTBOUND = 1,
    DIR_INBOUND  = 2,
} direction;

static const char *dir_arrow(direction d) {
    switch (d) {
    case DIR_OUTBOUND: return "\xe2\x86\x92"; // →
    case DIR_INBOUND:  return "\xe2\x86\x90"; // ←
    default:           return "\xe2\x86\x94"; // ↔
    }
}

// ─── Active connection tracking (for -t close timing) ────────────────────────

typedef struct conn_entry {
    char              key[160];
    conn_tuple        tuple;
    int32_t           pid;
    char              comm[64];
    direction         dir;
    double            start_at; // monotonic seconds
    uint8_t           tcp_state;
    struct conn_entry *next;
} conn_entry;

#define CONNDB_BUCKETS 1024
static conn_entry     *conndb[CONNDB_BUCKETS];
static pthread_mutex_t conn_mu = PTHREAD_MUTEX_INITIALIZER;

static unsigned str_hash(const char *s) {
    unsigned h = 2166136261u;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

// connDB get/put/delete. Caller holds conn_mu.
static conn_entry *db_get(const char *key) {
    for (conn_entry *e = conndb[str_hash(key) % CONNDB_BUCKETS]; e; e = e->next)
        if (!strcmp(e->key, key)) return e;
    return NULL;
}
static conn_entry *db_put(const char *key) {
    unsigned b = str_hash(key) % CONNDB_BUCKETS;
    for (conn_entry *e = conndb[b]; e; e = e->next)
        if (!strcmp(e->key, key)) return e;
    conn_entry *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    snprintf(e->key, sizeof e->key, "%s", key);
    e->next = conndb[b];
    conndb[b] = e;
    return e;
}
static void db_delete(const char *key) {
    unsigned b = str_hash(key) % CONNDB_BUCKETS;
    conn_entry **pp = &conndb[b];
    while (*pp) {
        if (!strcmp((*pp)->key, key)) {
            conn_entry *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

// ─── Local IP cache (direction fallback for container-netns sockets) ──────────

#define MAX_LOCAL_IPS 256
static char            local_ips[MAX_LOCAL_IPS][INET6_ADDRSTRLEN];
static int             local_ip_n;
static pthread_once_t  local_ips_once = PTHREAD_ONCE_INIT;

static void init_local_ips(void) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        char s[INET6_ADDRSTRLEN];
        if (p->ifa_addr->sa_family == AF_INET) {
            struct in_addr a = ((struct sockaddr_in *)p->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, &a, s, sizeof s);
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct in6_addr a = ((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, &a, s, sizeof s);
            // Strip a possible zone suffix that inet_ntop never adds but be safe.
            char *pct = strchr(s, '%');
            if (pct) *pct = 0;
        } else {
            continue;
        }
        if (local_ip_n >= MAX_LOCAL_IPS) break;
        // dedupe
        int dup = 0;
        for (int i = 0; i < local_ip_n; i++)
            if (!strcmp(local_ips[i], s)) { dup = 1; break; }
        if (!dup) snprintf(local_ips[local_ip_n++], INET6_ADDRSTRLEN, "%s", s);
    }
    freeifaddrs(ifa);
}

static bool is_local_ip(const uint8_t *ip, int len) {
    pthread_once(&local_ips_once, init_local_ips);
    char s[INET6_ADDRSTRLEN];
    ip_str(ip, len, s, sizeof s);
    for (int i = 0; i < local_ip_n; i++)
        if (!strcmp(local_ips[i], s)) return true;
    return false;
}

// ─── Async reverse DNS cache ─────────────────────────────────────────────────

typedef struct dns_ent {
    char            ip[INET6_ADDRSTRLEN];
    char            name[256]; // resolved PTR (without trailing dot), "" if none
    bool            launched;
    struct dns_ent *next;
} dns_ent;

#define DNS_BUCKETS 256
static dns_ent        *dns_cache[DNS_BUCKETS];
static pthread_mutex_t dns_mu = PTHREAD_MUTEX_INITIALIZER;

static dns_ent *dns_find(const char *ip) {
    for (dns_ent *e = dns_cache[str_hash(ip) % DNS_BUCKETS]; e; e = e->next)
        if (!strcmp(e->ip, ip)) return e;
    return NULL;
}
static dns_ent *dns_get_or_create(const char *ip) {
    dns_ent *e = dns_find(ip);
    if (e) return e;
    unsigned b = str_hash(ip) % DNS_BUCKETS;
    e = calloc(1, sizeof *e);
    if (!e) return NULL;
    snprintf(e->ip, sizeof e->ip, "%s", ip);
    e->next = dns_cache[b];
    dns_cache[b] = e;
    return e;
}

static void *dns_worker(void *arg) {
    char *ip = arg; // heap-owned
    char host[256] = "";

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t slen = 0;
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) slen = sizeof *s6;
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) slen = sizeof *s4;
    }
    if (slen) {
        char nb[256];
        if (getnameinfo((struct sockaddr *)&ss, slen, nb, sizeof nb,
                        NULL, 0, NI_NAMEREQD) == 0) {
            // net.LookupAddr returns FQDNs; trim a trailing dot to match
            // strings.TrimRight(names[0], ".").
            size_t L = strlen(nb);
            while (L && nb[L - 1] == '.') nb[--L] = 0;
            snprintf(host, sizeof host, "%s", nb);
        }
    }

    pthread_mutex_lock(&dns_mu);
    dns_ent *e = dns_get_or_create(ip);
    if (e) snprintf(e->name, sizeof e->name, "%s", host);
    pthread_mutex_unlock(&dns_mu);

    free(ip);
    return NULL;
}

// asyncReverseLookup: returns a cached hostname (copied into `out`), launching
// a background lookup on first call. Empty if unresolved / no PTR. Returns true
// when a non-empty name was written.
static bool async_reverse_lookup(const char *ip, char *out, size_t cap) {
    out[0] = 0;
    pthread_mutex_lock(&dns_mu);
    dns_ent *e = dns_find(ip);
    bool launched = e && e->launched;
    if (e && e->name[0]) snprintf(out, cap, "%s", e->name);
    if (!launched) {
        if (!e) e = dns_get_or_create(ip);
        if (e) e->launched = true;
    }
    pthread_mutex_unlock(&dns_mu);

    if (!launched) {
        char *arg = strdup(ip);
        if (arg) {
            pthread_t th;
            if (pthread_create(&th, NULL, dns_worker, arg) == 0)
                pthread_detach(th);
            else
                free(arg);
        }
    }
    return out[0] != 0;
}

// ─── Global options ───────────────────────────────────────────────────────────

#define MAX_WATCH 256
static int32_t watch_pids[MAX_WATCH];
static int     watch_n;

static bool  show_close;     // -t
static bool  show_update;    // -U
static bool  show_user;      // -u
static bool  show_reverse;   // -r
static bool  ipv4_only;      // -4
static bool  ipv6_only;      // -6
static bool  outbound_only;  // -O
static bool  show_errors = true;
static bool  color_force;    // -c
static bool  color_mode;
static FILE *out;

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// ─── Error helpers ────────────────────────────────────────────────────────────

static void fatalf(const char *f, ...) {
    va_list ap;
    va_start(ap, f);
    fputs("proc-trace-net: ", stderr);
    vfprintf(stderr, f, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void fatal(const char *msg) {
    fprintf(stderr, "proc-trace-net: %s\n", msg);
    exit(1);
}

// ─── NLA (netlink attribute) parsing ─────────────────────────────────────────

// A parsed flat attribute list. We index by stripped nla_type; conntrack
// types are small so a fixed table keyed by type is sufficient and avoids
// allocation. Stores a pointer+len into the source buffer (first occurrence
// wins on duplicates, like map assignment of distinct keys; conntrack does
// not duplicate these attrs).
#define NLA_MAX_TYPE 64
typedef struct {
    const uint8_t *val[NLA_MAX_TYPE];
    int            len[NLA_MAX_TYPE];
    bool           has[NLA_MAX_TYPE];
} nla_set;

static void parse_nla(const uint8_t *data, int n, nla_set *set) {
    memset(set, 0, sizeof *set);
    while (n >= 4) {
        uint16_t nla_len  = (uint16_t)(data[0] | (data[1] << 8));
        uint16_t nla_type = (uint16_t)(data[2] | (data[3] << 8));
        nla_type &= (uint16_t)~NLA_F_NESTED_;
        nla_type &= (uint16_t)~NLA_F_NET_BYTEORDER_;
        if (nla_len < 4) break;
        int end = nla_len;
        if (end > n) break;
        if (nla_type < NLA_MAX_TYPE && !set->has[nla_type]) {
            set->has[nla_type] = true;
            set->val[nla_type] = data + 4;
            set->len[nla_type] = end - 4;
        }
        int aligned = (end + 3) & ~3;
        if (aligned > n) break;
        data += aligned;
        n -= aligned;
    }
}

// parseTuple: extract src/dst IP, port, proto. tuple_attr is CTA_TUPLE_ORIG.
// Returns true on success.
static bool parse_tuple(const uint8_t *payload, int plen, uint16_t tuple_attr,
                        conn_tuple *t) {
    nla_set top;
    parse_nla(payload, plen, &top);
    if (tuple_attr >= NLA_MAX_TYPE || !top.has[tuple_attr]) return false;

    nla_set ta;
    parse_nla(top.val[tuple_attr], top.len[tuple_attr], &ta);

    memset(t, 0, sizeof *t);

    if (ta.has[CTA_TUPLE_IP_]) {
        nla_set ia;
        parse_nla(ta.val[CTA_TUPLE_IP_], ta.len[CTA_TUPLE_IP_], &ia);
        if (ia.has[CTA_IPV4_SRC_] && ia.len[CTA_IPV4_SRC_] == 4) {
            memcpy(t->src_ip, ia.val[CTA_IPV4_SRC_], 4);
            t->src_len = 4;
        }
        if (ia.has[CTA_IPV4_DST_] && ia.len[CTA_IPV4_DST_] == 4) {
            memcpy(t->dst_ip, ia.val[CTA_IPV4_DST_], 4);
            t->dst_len = 4;
        }
        if (ia.has[CTA_IPV6_SRC_] && ia.len[CTA_IPV6_SRC_] == 16) {
            memcpy(t->src_ip, ia.val[CTA_IPV6_SRC_], 16);
            t->src_len = 16;
        }
        if (ia.has[CTA_IPV6_DST_] && ia.len[CTA_IPV6_DST_] == 16) {
            memcpy(t->dst_ip, ia.val[CTA_IPV6_DST_], 16);
            t->dst_len = 16;
        }
    }

    if (ta.has[CTA_TUPLE_PROTO_]) {
        nla_set pa;
        parse_nla(ta.val[CTA_TUPLE_PROTO_], ta.len[CTA_TUPLE_PROTO_], &pa);
        if (pa.has[CTA_PROTO_NUM_] && pa.len[CTA_PROTO_NUM_] >= 1)
            t->proto = pa.val[CTA_PROTO_NUM_][0];
        if (pa.has[CTA_PROTO_SRC_PORT_] && pa.len[CTA_PROTO_SRC_PORT_] >= 2) {
            const uint8_t *v = pa.val[CTA_PROTO_SRC_PORT_];
            t->src_port = (uint16_t)((v[0] << 8) | v[1]); // big-endian
        }
        if (pa.has[CTA_PROTO_DST_PORT_] && pa.len[CTA_PROTO_DST_PORT_] >= 2) {
            const uint8_t *v = pa.val[CTA_PROTO_DST_PORT_];
            t->dst_port = (uint16_t)((v[0] << 8) | v[1]);
        }
    }

    if (t->src_len == 0 || t->dst_len == 0) return false;
    return true;
}

static uint8_t parse_tcp_state(const uint8_t *payload, int plen) {
    nla_set top;
    parse_nla(payload, plen, &top);
    if (!top.has[CTA_PROTOINFO_]) return 0;
    nla_set pi;
    parse_nla(top.val[CTA_PROTOINFO_], top.len[CTA_PROTOINFO_], &pi);
    if (!pi.has[CTA_PROTOINFO_TCP_]) return 0;
    nla_set tcp;
    parse_nla(pi.val[CTA_PROTOINFO_TCP_], pi.len[CTA_PROTOINFO_TCP_], &tcp);
    if (!tcp.has[CTA_PROTOINFO_TCP_STATE_] ||
        tcp.len[CTA_PROTOINFO_TCP_STATE_] < 1)
        return 0;
    return tcp.val[CTA_PROTOINFO_TCP_STATE_][0];
}

// ─── PID lookup via /proc/net/{tcp,udp} + inode scan ──────────────────────────

typedef struct {
    uint8_t  local_ip[16];
    int      local_len;
    uint16_t local_port;
    uint8_t  remote_ip[16];
    int      remote_len;
    uint16_t remote_port;
    uint64_t inode;
} proc_entry;

// "0100007F" → {127,0,0,1}: kernel prints v4 as a native-endian uint32.
static bool parse_hex_ipv4(const char *s, uint8_t *ip) {
    if (strlen(s) != 8) return false;
    char *e;
    unsigned long v = strtoul(s, &e, 16);
    if (*e) return false;
    ip[0] = (uint8_t)(v);
    ip[1] = (uint8_t)(v >> 8);
    ip[2] = (uint8_t)(v >> 16);
    ip[3] = (uint8_t)(v >> 24);
    return true;
}

// 32-char hex = 4 × 8-char LE words of struct in6_addr.
static bool parse_hex_ipv6(const char *s, uint8_t *ip) {
    if (strlen(s) != 32) return false;
    for (int i = 0; i < 4; i++) {
        char word[9];
        memcpy(word, s + i * 8, 8);
        word[8] = 0;
        char *e;
        unsigned long v = strtoul(word, &e, 16);
        if (*e) return false;
        ip[i * 4 + 0] = (uint8_t)(v);
        ip[i * 4 + 1] = (uint8_t)(v >> 8);
        ip[i * 4 + 2] = (uint8_t)(v >> 16);
        ip[i * 4 + 3] = (uint8_t)(v >> 24);
    }
    return true;
}

static uint16_t parse_hex_port(const char *s) {
    char *e;
    unsigned long v = strtoul(s, &e, 16);
    return (uint16_t)(v & 0xFFFF);
}

// ipsEq: compare two IPs, normalizing v4-mapped v6 to v4 first. Our v4 are
// already stored as 4-byte; conntrack never gives v4-mapped here, but mirror
// the Go logic by comparing by length+bytes.
static bool ips_eq(const uint8_t *a, int al, const uint8_t *b, int bl) {
    if (al != bl) return false;
    return memcmp(a, b, al) == 0;
}

#define MAX_PROC_ENTRIES 65536
static proc_entry proc_entries[MAX_PROC_ENTRIES];

static int read_proc_net_file(const char *filename, proc_entry *entries,
                              int cap) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    char line[1024];
    int n = 0;
    bool first = true;
    while (fgets(line, sizeof line, f)) {
        if (first) { first = false; continue; } // header
        // Split on whitespace; need fields[1] local, fields[2] remote,
        // fields[9] inode (0-based, like strings.Fields()).
        char *fields[16];
        int nf = 0;
        char *save = NULL;
        for (char *tok = strtok_r(line, " \t\n", &save);
             tok && nf < 16; tok = strtok_r(NULL, " \t\n", &save))
            fields[nf++] = tok;
        if (nf < 10) continue;

        char *la = fields[1], *ra = fields[2];
        char *lc = strchr(la, ':'), *rc = strchr(ra, ':');
        if (!lc || !rc) continue;
        *lc = 0;
        *rc = 0;
        char *lp = lc + 1, *rp = rc + 1;

        proc_entry e;
        memset(&e, 0, sizeof e);
        size_t hl = strlen(la);
        if (hl == 8) {
            if (!parse_hex_ipv4(la, e.local_ip) ||
                !parse_hex_ipv4(ra, e.remote_ip)) continue;
            e.local_len = e.remote_len = 4;
        } else if (hl == 32) {
            if (!parse_hex_ipv6(la, e.local_ip) ||
                !parse_hex_ipv6(ra, e.remote_ip)) continue;
            e.local_len = e.remote_len = 16;
        } else {
            continue;
        }
        char *endp;
        e.inode = strtoull(fields[9], &endp, 10);
        e.local_port = parse_hex_port(lp);
        e.remote_port = parse_hex_port(rp);
        if (n < cap) entries[n++] = e;
    }
    fclose(f);
    return n;
}

static uint64_t find_inode_with_dir(const conn_tuple *orig, direction *dir) {
    const char *files[2];
    int nfiles;
    if (orig->proto == 6) {
        files[0] = "/proc/net/tcp";
        files[1] = "/proc/net/tcp6";
        nfiles = 2;
    } else if (orig->proto == 17) {
        files[0] = "/proc/net/udp";
        files[1] = "/proc/net/udp6";
        nfiles = 2;
    } else {
        *dir = DIR_UNKNOWN;
        return 0;
    }

    for (int fi = 0; fi < nfiles; fi++) {
        int n = read_proc_net_file(files[fi], proc_entries, MAX_PROC_ENTRIES);
        for (int i = 0; i < n; i++) {
            proc_entry *e = &proc_entries[i];
            if (e->inode == 0) continue;
            // Outbound: local side owns the source port
            if (ips_eq(e->local_ip, e->local_len, orig->src_ip, orig->src_len) &&
                e->local_port == orig->src_port &&
                ips_eq(e->remote_ip, e->remote_len, orig->dst_ip, orig->dst_len) &&
                e->remote_port == orig->dst_port) {
                *dir = DIR_OUTBOUND;
                return e->inode;
            }
            // Inbound: local side owns the destination port
            if (ips_eq(e->local_ip, e->local_len, orig->dst_ip, orig->dst_len) &&
                e->local_port == orig->dst_port &&
                ips_eq(e->remote_ip, e->remote_len, orig->src_ip, orig->src_len) &&
                e->remote_port == orig->src_port) {
                *dir = DIR_INBOUND;
                return e->inode;
            }
        }
        // UDP fallback: unconnected sockets only have a local addr
        if (orig->proto == 17) {
            for (int i = 0; i < n; i++) {
                proc_entry *e = &proc_entries[i];
                if (e->inode == 0) continue;
                if (ips_eq(e->local_ip, e->local_len,
                           orig->src_ip, orig->src_len) &&
                    e->local_port == orig->src_port) {
                    *dir = DIR_OUTBOUND;
                    return e->inode;
                }
            }
        }
    }
    *dir = DIR_UNKNOWN;
    return 0;
}

static void inode_to_pid(uint64_t inode, int32_t *pid_out, char *comm,
                         size_t comm_cap) {
    *pid_out = 0;
    comm[0] = 0;
    char target[64];
    snprintf(target, sizeof target, "socket:[%llu]",
             (unsigned long long)inode);

    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *d;
    while ((d = readdir(proc))) {
        char *e;
        long pid = strtol(d->d_name, &e, 10);
        if (*e || pid <= 0) continue;
        char fddir[64];
        snprintf(fddir, sizeof fddir, "/proc/%ld/fd", pid);
        DIR *fdd = opendir(fddir);
        if (!fdd) continue;
        struct dirent *fe;
        bool found = false;
        while ((fe = readdir(fdd))) {
            if (fe->d_name[0] == '.') continue;
            char link[320], buf[80];
            snprintf(link, sizeof link, "%s/%s", fddir, fe->d_name);
            ssize_t r = readlink(link, buf, sizeof buf - 1);
            if (r < 0) continue;
            buf[r] = 0;
            if (!strcmp(buf, target)) {
                char cpath[64];
                snprintf(cpath, sizeof cpath, "/proc/%ld/comm", pid);
                FILE *cf = fopen(cpath, "r");
                if (cf) {
                    if (fgets(comm, (int)comm_cap, cf)) {
                        // strings.TrimRight(comm, "\n")
                        size_t L = strlen(comm);
                        while (L && comm[L - 1] == '\n') comm[--L] = 0;
                    }
                    fclose(cf);
                }
                *pid_out = (int32_t)pid;
                found = true;
                break;
            }
        }
        closedir(fdd);
        if (found) { closedir(proc); return; }
    }
    closedir(proc);
}

static void find_pid_and_dir(const conn_tuple *orig, int32_t *pid,
                             char *comm, size_t comm_cap, direction *dir) {
    *pid = 0;
    comm[0] = 0;
    uint64_t inode = find_inode_with_dir(orig, dir);
    if (inode == 0) {
        // Socket not in host netns (Docker). Fall back to IP heuristic.
        if (is_local_ip(orig->dst_ip, orig->dst_len))
            *dir = DIR_INBOUND;
        else if (is_local_ip(orig->src_ip, orig->src_len))
            *dir = DIR_OUTBOUND;
        return;
    }
    inode_to_pid(inode, pid, comm, comm_cap);
}

// ─── PID ancestry (for -p and CMD mode) ───────────────────────────────────────

static int32_t stat_ppid(int32_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    static char data[8192];
    size_t n = fread(data, 1, sizeof data - 1, f);
    fclose(f);
    data[n] = 0;
    // idx := bytes.LastIndexByte(data, ')')
    char *rp = NULL;
    for (size_t i = 0; i < n; i++)
        if (data[i] == ')') rp = data + i;
    if (!rp) return -1;
    char *rest = rp + 1;
    while (*rest == ' ') rest++;
    // fields[0]=state, fields[1]=ppid
    char *save = NULL;
    char *f0 = strtok_r(rest, " \t\n", &save);
    if (!f0) return -1;
    char *f1 = strtok_r(NULL, " \t\n", &save);
    if (!f1) return -1;
    char *e;
    long v = strtol(f1, &e, 10);
    if (e == f1) return -1;
    return (int32_t)v;
}

static bool is_descendant(int32_t pid) {
    int32_t seen[256];
    int seen_n = 0;
    for (int32_t p = pid; p > 1;) {
        for (int i = 0; i < seen_n; i++)
            if (seen[i] == p) return false;
        if (seen_n < 256) seen[seen_n++] = p;
        else return false;
        int32_t ppid = stat_ppid(p);
        if (ppid <= 0) return false;
        for (int i = 0; i < watch_n; i++)
            if (ppid == watch_pids[i]) return true;
        p = ppid;
    }
    return false;
}

static bool is_watched(int32_t pid) {
    if (pid <= 0) return false;
    for (int i = 0; i < watch_n; i++)
        if (pid == watch_pids[i]) return true;
    return is_descendant(pid);
}

// ─── Process info ─────────────────────────────────────────────────────────────

static const char *proc_user(int32_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) != 0) return "?";
    struct passwd *pw = getpwuid(st.st_uid);
    if (!pw) {
        static char b[16];
        snprintf(b, sizeof b, "%u", (unsigned)st.st_uid);
        return b;
    }
    static char b[256];
    snprintf(b, sizeof b, "%s", pw->pw_name);
    return b;
}

// ─── Output ───────────────────────────────────────────────────────────────────

static void print_event(const conn_tuple *orig, int32_t pid, const char *comm,
                         direction dir, const char *event,
                         const char *extra) {
    // Build the line incrementally; clr()'s rotating pool tolerates this
    // because we fputs each colored field immediately rather than holding
    // many live pointers across one printf.
    bool C = color_mode;

    // PID
    if (pid > 0) {
        char b[16];
        snprintf(b, sizeof b, "%5d", pid);
        fputs(clr(C, "33", b), out);
    } else {
        fputs(clr(C, "2", "    ?"), out);
    }
    fputc(' ', out);

    // Comm (12-wide)
    {
        char b[64];
        snprintf(b, sizeof b, "%-12s", (comm && comm[0]) ? comm : "?");
        fputs(clr(C, (comm && comm[0]) ? "96" : "2", b), out);
    }

    // User
    if (show_user && pid > 0) {
        const char *uname = proc_user(pid);
        char b[280];
        snprintf(b, sizeof b, " <%s>", uname);
        fputs(clr(C, !strcmp(uname, "root") ? "91" : "92", b), out);
    }
    fputc(' ', out);

    // Protocol (4-wide)
    {
        char b[16];
        snprintf(b, sizeof b, "%-4s", proto_str(orig->proto));
        fputs(clr(C, "2", b), out);
    }
    fputc(' ', out);

    // Source address (24-wide)
    {
        char ip[INET6_ADDRSTRLEN], s[64], b[80];
        ip_str(orig->src_ip, orig->src_len, ip, sizeof ip);
        snprintf(s, sizeof s, "%s:%d", ip, orig->src_port);
        snprintf(b, sizeof b, "%-24s", s);
        fputs(clr(C, "32", b), out);
    }
    fputc(' ', out);

    // Direction indicator / event marker
    if (!strcmp(event, "CLOSED"))
        fputs(clr(C, "31", "\xc3\x97"), out); // ×
    else if (!strcmp(event, "UPDATE"))
        fputs(clr(C, "35", "\xe2\x87\x92"), out); // ⇒
    else
        fputs(clr(C, "36", dir_arrow(dir)), out);
    fputc(' ', out);

    // Destination address (24-wide)
    {
        char ip[INET6_ADDRSTRLEN], s[64], b[80];
        ip_str(orig->dst_ip, orig->dst_len, ip, sizeof ip);
        snprintf(s, sizeof s, "%s:%d", ip, orig->dst_port);
        snprintf(b, sizeof b, "%-24s", s);
        fputs(clr(C, "33", b), out);
    }

    // Reverse DNS (async; empty on first occurrence)
    if (show_reverse) {
        char lookup[INET6_ADDRSTRLEN];
        if (dir == DIR_INBOUND)
            ip_str(orig->src_ip, orig->src_len, lookup, sizeof lookup);
        else
            ip_str(orig->dst_ip, orig->dst_len, lookup, sizeof lookup);
        char host[256], b[300];
        if (async_reverse_lookup(lookup, host, sizeof host)) {
            snprintf(b, sizeof b, " [%s]", host);
            fputs(clr(C, "2", b), out);
        }
    }

    // Extra: state name (UPDATE) or elapsed time (CLOSED)
    if (extra && extra[0]) {
        fputc(' ', out);
        fputs(clr(C, "36", extra), out);
    }

    fputc('\n', out);
    fflush(out);
}

// ─── Event handlers ───────────────────────────────────────────────────────────

static void handle_new(const char *key, const conn_tuple *orig,
                        const uint8_t *payload, int plen) {
    int32_t pid;
    char comm[64];
    direction dir;
    find_pid_and_dir(orig, &pid, comm, sizeof comm, &dir);

    if (watch_n > 0 && !is_watched(pid)) return;
    if (outbound_only && dir == DIR_INBOUND) return;

    uint8_t tcp_state = 0;
    if (orig->proto == 6) tcp_state = parse_tcp_state(payload, plen);

    pthread_mutex_lock(&conn_mu);
    conn_entry *e = db_put(key);
    if (e) {
        e->tuple = *orig;
        e->pid = pid;
        snprintf(e->comm, sizeof e->comm, "%s", comm);
        e->dir = dir;
        e->start_at = mono_now();
        e->tcp_state = tcp_state;
    }
    pthread_mutex_unlock(&conn_mu);

    print_event(orig, pid, comm, dir, "", "");
}

static void handle_update(const char *key, const conn_tuple *orig,
                          const uint8_t *payload, int plen) {
    pthread_mutex_lock(&conn_mu);
    conn_entry *ent = db_get(key);
    int32_t pid = 0;
    char comm[64] = "";
    direction dir = DIR_UNKNOWN;
    if (ent) {
        pid = ent->pid;
        snprintf(comm, sizeof comm, "%s", ent->comm);
        dir = ent->dir;
    }
    pthread_mutex_unlock(&conn_mu);

    if (watch_n > 0 && !is_watched(pid)) return;
    if (outbound_only && dir == DIR_INBOUND) return;

    char state_name[16] = "";
    if (orig->proto == 6) {
        uint8_t s = parse_tcp_state(payload, plen);
        snprintf(state_name, sizeof state_name, "%s", tcp_state_name(s));
        pthread_mutex_lock(&conn_mu);
        conn_entry *e2 = db_get(key); // re-fetch: ent may be stale post-unlock
        if (e2) e2->tcp_state = s;
        pthread_mutex_unlock(&conn_mu);
    }

    print_event(orig, pid, comm, dir, "UPDATE", state_name);
}

static void handle_destroy(const char *key, const conn_tuple *orig) {
    pthread_mutex_lock(&conn_mu);
    conn_entry *ent = db_get(key);
    int32_t pid = 0;
    char comm[64] = "";
    direction dir = DIR_UNKNOWN;
    double start_at = 0;
    bool had = ent != NULL;
    if (ent) {
        pid = ent->pid;
        snprintf(comm, sizeof comm, "%s", ent->comm);
        dir = ent->dir;
        start_at = ent->start_at;
    }
    db_delete(key);
    pthread_mutex_unlock(&conn_mu);

    if (!had) return; // connection pre-dates our start
    if (watch_n > 0 && !is_watched(pid)) return;

    char elapsed[32];
    snprintf(elapsed, sizeof elapsed, "%.3fs", mono_now() - start_at);
    print_event(orig, pid, comm, dir, "CLOSED", elapsed);
}

// ─── Netlink message dispatch ─────────────────────────────────────────────────

// Iterate nlmsghdr-framed messages (replaces syscall.ParseNetlinkMessage).
static void process_nl_msgs(const uint8_t *data, int len) {
    while (len >= (int)sizeof(struct nlmsghdr)) {
        const struct nlmsghdr *nlh = (const struct nlmsghdr *)data;
        unsigned mlen = nlh->nlmsg_len;
        if (mlen < sizeof(struct nlmsghdr) || (int)mlen > len) return;

        int t = (int)nlh->nlmsg_type;
        if (t == MSG_CT_NEW || t == MSG_CT_DELETE) {
            const uint8_t *msg_data = data + NLMSG_HDRLEN;
            int data_len = (int)mlen - NLMSG_HDRLEN;
            if (data_len >= NFGEN_MSG_SIZE) {
                const uint8_t *payload = msg_data + NFGEN_MSG_SIZE;
                int plen = data_len - NFGEN_MSG_SIZE;

                conn_tuple orig;
                if (parse_tuple(payload, plen, CTA_TUPLE_ORIG_, &orig)) {
                    bool is4 = orig.src_len == 4;
                    bool skip = false;
                    if (ipv4_only && !is4) skip = true;
                    if (ipv6_only && is4) skip = true;
                    if (orig.proto != 6 && orig.proto != 17) skip = true;

                    if (!skip) {
                        char key[160];
                        tuple_key(&orig, key, sizeof key);
                        bool is_new = (t == MSG_CT_NEW);
                        bool is_create =
                            (nlh->nlmsg_flags & NLM_F_CREATE_) != 0;

                        if (is_new && is_create) {
                            handle_new(key, &orig, payload, plen);
                        } else if (is_new && !is_create && show_update) {
                            handle_update(key, &orig, payload, plen);
                        } else if (!is_new && show_close) {
                            handle_destroy(key, &orig);
                        } else if (!is_new) {
                            pthread_mutex_lock(&conn_mu);
                            db_delete(key);
                            pthread_mutex_unlock(&conn_mu);
                        }
                    }
                }
            }
        }

        unsigned aligned = NLMSG_ALIGN(mlen);
        if ((int)aligned >= len) break;
        data += aligned;
        len -= (int)aligned;
    }
}

// ─── CMD-mode child reaper ────────────────────────────────────────────────────

// Background thread mirroring net.go's `go func(){ cmd.Wait();
// time.Sleep(300ms); os.Exit(0) }()`. Keeping the netlink recv() in the
// main loop blocking (exactly like Go's syscall.Recvfrom).
static pid_t cmd_child_pid;

static void *child_waiter(void *arg) {
    (void)arg;
    int status;
    while (waitpid(cmd_child_pid, &status, 0) < 0 && errno == EINTR)
        ;
    struct timespec ts = {0, 300 * 1000 * 1000};
    nanosleep(&ts, NULL);
    _exit(0);
}

// ─── Usage ────────────────────────────────────────────────────────────────────

static void usage(void) {
    const char *bold    = "\033[1m";
    const char *dim     = "\033[2m";
    const char *reset   = "\033[0m";
    const char *cyan    = "\033[36m";
    const char *yellow  = "\033[33m";
    const char *green   = "\033[32m";
    const char *magenta = "\033[35m";
    FILE *e = stderr;
    fprintf(e, "\n  %s%s🌐 proc-trace-net%s %s%s%s — system-wide network connection tracer for Linux\n\n",
            bold, cyan, reset, dim, tracep_version, reset);
    fprintf(e, "  %sRequires:%s root or CAP_NET_ADMIN, nf_conntrack kernel module\n\n",
            bold, reset);
    fprintf(e, "  %sUsage:%s\n", bold, reset);
    fprintf(e, "    proc-trace-net %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n",
            dim, reset, yellow, reset);
    fprintf(e, "  %sFlags:%s\n", bold, reset);
    fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n",
            yellow, reset, dim, reset);
    fprintf(e, "    ⏱️   %s-t%s          show connection close events with duration\n",
            yellow, reset);
    fprintf(e, "    🔄  %s-U%s          show TCP state update events %s(ESTABLISHED, FIN_WAIT, ...)%s\n",
            yellow, reset, dim, reset);
    fprintf(e, "    👤  %s-u%s          print owning user of each connection\n",
            yellow, reset);
    fprintf(e, "    🔍  %s-r%s          reverse DNS lookup for remote IPs %s(async, cached)%s\n",
            yellow, reset, dim, reset);
    fprintf(e, "    4️⃣   %s-4%s          IPv4 connections only\n", yellow, reset);
    fprintf(e, "    6️⃣   %s-6%s          IPv6 connections only\n", yellow, reset);
    fprintf(e, "    📤  %s-O%s          outbound connections only %s(hide inbound/unknown)%s\n",
            yellow, reset, dim, reset);
    fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset);
    fprintf(e, "    📝  %s-o%s %sFILE%s      write output to FILE instead of stdout\n",
            yellow, reset, cyan, reset);
    fprintf(e, "    🎯  %s-p%s %sPID%s       trace PIDs and their descendants %s(comma-separate for multiple)%s\n",
            yellow, reset, cyan, reset, dim, reset);
    fprintf(e, "\n  %sOutput columns:%s\n", bold, reset);
    fprintf(e, "    PID  COMM         PROTO  SRC_IP:PORT              %s→%s  DST_IP:PORT\n",
            cyan, reset);
    fprintf(e, "    %s→%s outbound  %s←%s inbound  %s↔%s unknown direction\n",
            cyan, reset, cyan, reset, cyan, reset);
    fprintf(e, "    %s⇒%s TCP state update (with -U)   %s×%s connection closed (with -t)\n\n",
            magenta, reset, yellow, reset);
    fprintf(e, "  %sExamples:%s\n", bold, reset);
    fprintf(e, "    %s# trace all connections system-wide%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-net %s-ctu%s\n\n", green, reset);
    fprintf(e, "    %s# trace connections made by a command%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-net %s-ctr%s curl https://example.com\n\n",
            green, reset);
    fprintf(e, "    %s# watch all nginx worker connections%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-net %s-p%s $(pgrep nginx | paste -sd,)\n\n",
            green, reset);
    fprintf(e, "    %s# log everything to a file%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-net %s-Qo%s /var/log/connections.log\n\n",
            green, reset);
    exit(1);
}

// ─── main ─────────────────────────────────────────────────────────────────────

int net_main(int argc, char **argv) {
    out = stdout;
    char **cmd_args = NULL;
    int    cmd_argc = 0;
    char  *out_file = NULL;

    // args := os.Args[1:]
    for (int i = 1; i < argc; i++) {
        char *a = argv[i];
        if (strlen(a) < 2 || a[0] != '-') {
            cmd_args = &argv[i];
            cmd_argc = argc - i;
            break;
        }
        for (char *ch = a + 1; *ch; ch++) {
            switch (*ch) {
            case 'c': color_force = true; break;
            case 't': show_close = true; break;
            case 'U': show_update = true; break;
            case 'u': show_user = true; break;
            case 'r': show_reverse = true; break;
            case '4': ipv4_only = true; break;
            case '6': ipv6_only = true; break;
            case 'O': outbound_only = true; break;
            case 'Q': show_errors = false; break;
            case 'p': {
                if (i + 1 >= argc) fatal("flag -p requires an argument");
                i++;
                char *dup = strdup(argv[i]);
                char *save = NULL;
                for (char *s = strtok_r(dup, ",", &save); s;
                     s = strtok_r(NULL, ",", &save)) {
                    while (*s == ' ' || *s == '\t') s++;
                    size_t L = strlen(s);
                    while (L && (s[L - 1] == ' ' || s[L - 1] == '\t'))
                        s[--L] = 0;
                    if (!*s) continue;
                    char *e;
                    long pid = strtol(s, &e, 10);
                    if (*e || pid <= 0)
                        fatalf("-p: invalid PID: %s", s);
                    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
                        fatalf("-p %ld: no such process", pid);
                    if (watch_n < MAX_WATCH)
                        watch_pids[watch_n++] = (int32_t)pid;
                }
                free(dup);
                // Skip the rest of this clustered arg (Go consumes args[i]
                // and continues the outer loop, not the inner rune loop).
                goto next_arg;
            }
            case 'o':
                if (i + 1 >= argc) fatal("flag -o requires an argument");
                i++;
                out_file = argv[i];
                goto next_arg;
            case 'h':
                usage();
                break;
            default:
                fatalf("unknown flag -%c", *ch);
            }
        }
    next_arg:;
    }

    if (out_file) {
        FILE *f = fopen(out_file, "a");
        if (!f) fatalf("open %s: %s", out_file, strerror(errno));
        out = f;
    }

    if (color_force) {
        color_mode = true;
    } else if (getenv("NO_COLOR") == NULL) {
        color_mode = is_terminal(out);
    }

    uint32_t groups = NF_CT_NEW | NF_CT_DESTROY;
    if (show_update) groups |= NF_CT_UPDATE;

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER_);
    if (fd < 0)
        fatalf("socket: %s\nhint: requires CAP_NET_ADMIN (run as root)",
               strerror(errno));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = groups;
    sa.nl_pid = (uint32_t)getpid();
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0)
        fatalf("bind: %s\nhint: is nf_conntrack loaded? try: modprobe nf_conntrack",
               strerror(errno));

    // CMD mode: launch command, trace only it + descendants, exit ~300ms
    // after it exits.
    if (cmd_argc > 0) {
        pid_t pid = fork();
        if (pid < 0)
            fatalf("exec %s: %s", cmd_args[0], strerror(errno));
        if (pid == 0) {
            execvp(cmd_args[0], cmd_args);
            // exec failed in child
            fprintf(stderr, "proc-trace-net: exec %s: %s\n",
                    cmd_args[0], strerror(errno));
            _exit(127);
        }
        if (watch_n < MAX_WATCH) watch_pids[watch_n++] = (int32_t)pid;
        cmd_child_pid = pid;
        pthread_t wt;
        if (pthread_create(&wt, NULL, child_waiter, NULL) == 0)
            pthread_detach(wt);
    }

    uint8_t *buf = malloc(1 << 20); // 1 MB — enough for large bursts
    if (!buf) fatal("out of memory");
    for (;;) {
        ssize_t n = recv(fd, buf, 1 << 20, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (show_errors)
                fprintf(stderr, "proc-trace-net: recvfrom: %s\n",
                        strerror(errno));
            continue;
        }
        process_nl_msgs(buf, (int)n);
    }

    // unreachable
}

#endif // __linux__
