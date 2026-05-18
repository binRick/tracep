// exec — trace exec() calls system-wide via the Linux proc connector
// (port of internal/exectrace). Linux-only: subscribes to the netlink
// NETLINK_CONNECTOR proc-event multicast group, walks the process tree
// to attribute depth, and prints each exec()/exit() with the same flags,
// colors, and error strings as the Go original. Off Linux it prints the
// exact non-Linux stub message (exec_other.go) and returns 1.
#define _GNU_SOURCE
#include "common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)

#include <linux/netlink.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

// ─── Netlink / proc connector constants ──────────────────────────────────────

#define NETLINK_CONNECTOR_PROTO 11
#define CN_IDX_PROC             1
#define CN_VAL_PROC             1
#define PROC_CN_MCAST_LISTEN    1
#define PROC_CN_MCAST_IGNORE    2

#define PROC_EVENT_EXEC 0x00000002u
#define PROC_EVENT_EXIT 0x80000000u

#define NLMSG_HDR_SIZE 16 // sizeof(struct nlmsghdr)
#define CN_MSG_SIZE    20 // sizeof(struct cn_msg): 4+4+4+4+2+2
#define PROC_EVT_HDR   16 // what(4)+cpu(4)+ts(8)

// ─── Global options ───────────────────────────────────────────────────────────

static int32_t  watchPIDs[256];
static int      nWatchPIDs;
static bool     showCwd;
static bool     showEnv;
static bool     flatMode;
static bool     fullPath;
static bool     showArgs   = true;
static bool     showErrors = true;
static bool     showExit;
static bool     showUser;
static bool     colorMode;
static bool     colorForce;
static FILE    *out; // default stdout (set in exec_main)

// ─── Proc database (pid → entry), open-addressing hash map ───────────────────

typedef struct {
    bool     used;
    int32_t  pid;
    int      depth;
    uint64_t startNs;
    char    *cmdline; // first arg, for exit line (heap, may be NULL/empty)
} pidEntry;

#define PIDDB_CAP 16384 // power of two; load kept well under 1/2
static pidEntry pidDB[PIDDB_CAP];
static int      pidDBLen;

static unsigned piddb_hash(int32_t pid) {
    // Knuth multiplicative hash; mask to table size.
    return ((unsigned)pid * 2654435761u) & (PIDDB_CAP - 1);
}

// piddb_find returns the entry for pid, or NULL if absent.
static pidEntry *piddb_find(int32_t pid) {
    unsigned i = piddb_hash(pid);
    for (unsigned probe = 0; probe < PIDDB_CAP; probe++) {
        pidEntry *e = &pidDB[(i + probe) & (PIDDB_CAP - 1)];
        if (!e->used) return NULL;
        if (e->pid == pid) return e;
    }
    return NULL;
}

// piddb_get returns the entry for pid, creating a zeroed one if absent.
// *created is set to whether a new entry was made.
static pidEntry *piddb_get(int32_t pid, bool *created) {
    unsigned i = piddb_hash(pid);
    for (unsigned probe = 0; probe < PIDDB_CAP; probe++) {
        pidEntry *e = &pidDB[(i + probe) & (PIDDB_CAP - 1)];
        if (e->used && e->pid == pid) { if (created) *created = false; return e; }
        if (!e->used) {
            e->used    = true;
            e->pid     = pid;
            e->depth   = 0;
            e->startNs = 0;
            e->cmdline = NULL;
            pidDBLen++;
            if (created) *created = true;
            return e;
        }
    }
    return NULL; // table full — should not happen at PIDDB_CAP
}

// piddb_delete removes pid (Robin-Hood-free: rehash the cluster after the hole).
static void piddb_delete(int32_t pid) {
    unsigned i = piddb_hash(pid);
    unsigned slot = (unsigned)-1;
    for (unsigned probe = 0; probe < PIDDB_CAP; probe++) {
        pidEntry *e = &pidDB[(i + probe) & (PIDDB_CAP - 1)];
        if (!e->used) return;
        if (e->pid == pid) { slot = (i + probe) & (PIDDB_CAP - 1); break; }
    }
    if (slot == (unsigned)-1) return;
    free(pidDB[slot].cmdline);
    pidDB[slot].used    = false;
    pidDB[slot].cmdline = NULL;
    pidDBLen--;
    // Reinsert the following contiguous cluster.
    unsigned j = slot;
    for (;;) {
        j = (j + 1) & (PIDDB_CAP - 1);
        pidEntry *e = &pidDB[j];
        if (!e->used) break;
        pidEntry tmp = *e;
        e->used    = false;
        e->cmdline = NULL;
        pidDBLen--;
        bool created;
        pidEntry *ne = piddb_get(tmp.pid, &created);
        ne->depth   = tmp.depth;
        ne->startNs = tmp.startNs;
        ne->cmdline = tmp.cmdline;
    }
}

// ─── Color helpers ────────────────────────────────────────────────────────────

// c wraps s in an ANSI color when colorMode is on (clr() from common.h is
// the byte-for-byte twin of exec.go's clr; colorMode gates it).
static const char *c(const char *code, const char *s) {
    return clr(colorMode, code, s);
}

// isWatchRoot reports whether pid is one of the watched root PIDs.
static bool isWatchRoot(int32_t pid) {
    for (int i = 0; i < nWatchPIDs; i++)
        if (watchPIDs[i] == pid) return true;
    return false;
}

// ─── Error helpers ────────────────────────────────────────────────────────────

static void runtimeErr(const char *f, ...) {
    if (!showErrors) return;
    va_list ap;
    va_start(ap, f);
    vfprintf(stderr, f, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void fatalf(const char *f, ...) {
    fputs("proc-trace-exec: ", stderr);
    va_list ap;
    va_start(ap, f);
    vfprintf(stderr, f, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void fatal(const char *msg) {
    fprintf(stderr, "proc-trace-exec: %s\n", msg);
    exit(1);
}

// ─── Signal names ─────────────────────────────────────────────────────────────

static const char *sigName(int sig) {
    static const struct { int n; const char *s; } names[] = {
        {1, "SIGHUP"},  {2, "SIGINT"},  {3, "SIGQUIT"}, {4, "SIGILL"},
        {5, "SIGTRAP"}, {6, "SIGABRT"}, {7, "SIGBUS"},  {8, "SIGFPE"},
        {9, "SIGKILL"}, {10, "SIGUSR1"},{11, "SIGSEGV"},{12, "SIGUSR2"},
        {13, "SIGPIPE"},{14, "SIGALRM"},{15, "SIGTERM"},{17, "SIGCHLD"},
        {18, "SIGCONT"},{19, "SIGSTOP"},{20, "SIGTSTP"},{21, "SIGTTIN"},
        {22, "SIGTTOU"},{23, "SIGURG"}, {24, "SIGXCPU"},{25, "SIGXFSZ"},
        {26, "SIGVTALRM"},{27, "SIGPROF"},{28, "SIGWINCH"},{29, "SIGIO"},
        {30, "SIGPWR"}, {31, "SIGSYS"},
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (names[i].n == sig) return names[i].s;
    static char b[16];
    snprintf(b, sizeof b, "SIG%d", sig);
    return b;
}

// ─── Little-endian readers ────────────────────────────────────────────────────

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const uint8_t *p) {
    return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;       p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static void put16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
}

// ─── /proc helpers ────────────────────────────────────────────────────────────

// read_file slurps path into a heap buffer; *len gets the byte count.
// Returns NULL on error. Caller frees.
static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) { fclose(f); return NULL; }
    for (;;) {
        if (n == cap) {
            size_t ncap = cap * 2;
            uint8_t *nb = realloc(buf, ncap);
            if (!nb) { free(buf); fclose(f); return NULL; }
            buf = nb;
            cap = ncap;
        }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0) break;
    }
    fclose(f);
    *len = n;
    return buf;
}

// readCmdline: NUL-separated argv from /proc/<pid>/cmdline. Returns count;
// argv slots strdup'd into out[] (caller frees each). Trailing NULs trimmed.
static int readCmdline(int32_t pid, char ***argvOut) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    size_t len;
    uint8_t *data = read_file(path, &len);
    if (!data || len == 0) { free(data); *argvOut = NULL; return 0; }
    while (len > 0 && data[len - 1] == 0) len--; // bytes.TrimRight "\x00"
    if (len == 0) { free(data); *argvOut = NULL; return 0; }
    // Split on NUL (bytes.Split → one extra empty element if trailing sep,
    // but trailing NULs are trimmed so behaviour matches Go exactly).
    int cap = 8, n = 0;
    char **v = malloc((size_t)cap * sizeof *v);
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || data[i] == 0) {
            if (n == cap) { cap *= 2; v = realloc(v, (size_t)cap * sizeof *v); }
            size_t slen = i - start;
            char *s = malloc(slen + 1);
            memcpy(s, data + start, slen);
            s[slen] = 0;
            v[n++] = s;
            start = i + 1;
            if (i == len) break;
        }
    }
    free(data);
    *argvOut = v;
    return n;
}
static void freeArgv(char **v, int n) {
    if (!v) return;
    for (int i = 0; i < n; i++) free(v[i]);
    free(v);
}

// readComm: /proc/<pid>/comm with trailing newline(s) trimmed. Heap; "" if err.
static char *readComm(int32_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/comm", pid);
    size_t len;
    uint8_t *data = read_file(path, &len);
    if (!data) return strdup("");
    while (len > 0 && data[len - 1] == '\n') len--; // strings.TrimRight "\n"
    char *s = malloc(len + 1);
    memcpy(s, data, len);
    s[len] = 0;
    free(data);
    return s;
}

// readFirstArg: basename of argv[0], or comm if no cmdline. Heap.
static char *readFirstArg(int32_t pid) {
    char **argv;
    int n = readCmdline(pid, &argv);
    if (n == 0) {
        freeArgv(argv, n);
        return readComm(pid);
    }
    // filepath.Base of argv[0].
    char *a0 = argv[0];
    const char *base = a0;
    for (char *p = a0; *p; p++)
        if (*p == '/') base = p + 1;
    char *r;
    if (*base == 0) {
        // filepath.Base: empty → ".", all-slashes → "/".
        r = strdup(*a0 ? "/" : ".");
    } else {
        r = strdup(base);
    }
    freeArgv(argv, n);
    return r;
}

static char *readExe(int32_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/exe", pid);
    char buf[4096];
    ssize_t r = readlink(path, buf, sizeof buf - 1);
    if (r < 0) return strdup("");
    buf[r] = 0;
    return strdup(buf);
}

static char *procCwd(int32_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cwd", pid);
    char buf[4096];
    ssize_t r = readlink(path, buf, sizeof buf - 1);
    if (r < 0)
        return strdup(errno == EACCES ? "EACCES" : "EUNKNOWN");
    buf[r] = 0;
    return strdup(buf);
}

// readEnviron: NUL-separated env from /proc/<pid>/environ. Same shape as
// readCmdline. Returns count; *envOut strdup'd slots.
static int readEnviron(int32_t pid, char ***envOut) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/environ", pid);
    size_t len;
    uint8_t *data = read_file(path, &len);
    if (!data || len == 0) { free(data); *envOut = NULL; return 0; }
    while (len > 0 && data[len - 1] == 0) len--;
    if (len == 0) { free(data); *envOut = NULL; return 0; }
    int cap = 8, n = 0;
    char **v = malloc((size_t)cap * sizeof *v);
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || data[i] == 0) {
            if (n == cap) { cap *= 2; v = realloc(v, (size_t)cap * sizeof *v); }
            size_t slen = i - start;
            char *s = malloc(slen + 1);
            memcpy(s, data + start, slen);
            s[slen] = 0;
            v[n++] = s;
            start = i + 1;
            if (i == len) break;
        }
    }
    free(data);
    *envOut = v;
    return n;
}

// procUser: username owning /proc/<pid>, falling back to the numeric uid,
// or "?" on stat failure. Returned pointer is to a static buffer.
static const char *procUser(int32_t pid) {
    static char buf[256];
    char path[64];
    snprintf(path, sizeof path, "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) != 0) return "?";
    struct passwd *pw = getpwuid(st.st_uid);
    if (!pw) {
        snprintf(buf, sizeof buf, "%u", (unsigned)st.st_uid);
        return buf;
    }
    snprintf(buf, sizeof buf, "%s", pw->pw_name);
    return buf;
}

// statPPID reads the ppid from /proc/<pid>/stat (handles parens in comm).
// Returns the ppid (0 = parent of PID 1), or -1 on read error.
static int32_t statPPID(int32_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    size_t len;
    uint8_t *data = read_file(path, &len);
    if (!data) return -1;
    // bytes.LastIndexByte(data, ')')
    long idx = -1;
    for (long i = (long)len - 1; i >= 0; i--)
        if (data[i] == ')') { idx = i; break; }
    if (idx < 0) { free(data); return -1; }
    // rest = TrimLeft(data[idx+1:], " "); fields = Fields(rest); fields[1].
    size_t p = (size_t)idx + 1;
    while (p < len && data[p] == ' ') p++;
    // Field 0 = state, field 1 = ppid (whitespace-separated; strings.Fields
    // splits on Unicode space — /proc/.../stat uses single ' ' only).
    int field = 0;
    char ppidbuf[32];
    while (p < len) {
        // skip whitespace between fields
        while (p < len && (data[p] == ' ' || data[p] == '\t' ||
                           data[p] == '\n' || data[p] == '\r' ||
                           data[p] == '\v' || data[p] == '\f'))
            p++;
        if (p >= len) break;
        size_t fstart = p;
        while (p < len && !(data[p] == ' ' || data[p] == '\t' ||
                            data[p] == '\n' || data[p] == '\r' ||
                            data[p] == '\v' || data[p] == '\f'))
            p++;
        if (field == 1) {
            size_t flen = p - fstart;
            if (flen >= sizeof ppidbuf) { free(data); return -1; }
            memcpy(ppidbuf, data + fstart, flen);
            ppidbuf[flen] = 0;
            char *end;
            errno = 0;
            long v = strtol(ppidbuf, &end, 10);
            if (end == ppidbuf || *end != 0 || errno != 0 ||
                v < -2147483648L || v > 2147483647L) {
                free(data);
                return -1;
            }
            free(data);
            return (int32_t)v;
        }
        field++;
    }
    free(data);
    return -1; // len(fields) < 2
}

// ─── Depth / ancestry ─────────────────────────────────────────────────────────

// pidDepth returns the tree depth of pid relative to the nearest watchPID,
// or -1 if pid is not a descendant of any watched root.
static int pidDepth(int32_t pid) {
    if (isWatchRoot(pid)) return 0;
    int32_t ppid = statPPID(pid);
    if (ppid < 0) {
        runtimeErr("proc-trace-exec: process vanished before we found its parent: pid %d",
                   (int)pid);
        return -1;
    }
    if (ppid == 0) return -1; // top of tree, no watch root
    if (isWatchRoot(ppid)) return 0;

    pidEntry *ent = piddb_find(ppid);
    if (ent) return ent->depth + 1;

    int d = pidDepth(ppid);
    if (d < 0) return -1;
    return d + 1;
}

// ─── Output formatting ────────────────────────────────────────────────────────

// indentStr writes "  " * depth into dst (cap bytes); returns dst.
static char *indentStr(int depth, char *dst, size_t cap) {
    if (flatMode || depth <= 0 || cap == 0) { if (cap) dst[0] = 0; return dst; }
    size_t w = 0;
    for (int i = 0; i < depth && w + 2 < cap; i++) {
        dst[w++] = ' ';
        dst[w++] = ' ';
    }
    dst[w] = 0;
    return dst;
}

static void printExec(int32_t pid, int depth, uint64_t tsNs) {
    (void)tsNs;
    char indent[1024];
    indentStr(depth, indent, sizeof indent);

    // Build the line into a growable buffer (env can be large).
    size_t cap = 8192, w = 0;
    char *sb = malloc(cap);
#define APPEND(str)                                                       \
    do {                                                                  \
        const char *_s = (str);                                           \
        size_t _l = strlen(_s);                                           \
        while (w + _l + 1 > cap) { cap *= 2; sb = realloc(sb, cap); }      \
        memcpy(sb + w, _s, _l);                                           \
        w += _l;                                                          \
        sb[w] = 0;                                                        \
    } while (0)
#define APPEND_CH(ch)                                                     \
    do {                                                                  \
        while (w + 2 > cap) { cap *= 2; sb = realloc(sb, cap); }           \
        sb[w++] = (ch);                                                   \
        sb[w] = 0;                                                         \
    } while (0)

    APPEND(indent);
    char pidstr[16];
    snprintf(pidstr, sizeof pidstr, "%d", (int)pid);
    APPEND(c("33", pidstr));
    if (showExit) APPEND(c("32", "+"));

    if (showUser) {
        const char *name = procUser(pid);
        char wrapped[300];
        snprintf(wrapped, sizeof wrapped, " <%s>", name);
        if (!strcmp(name, "root")) APPEND(c("91", wrapped));
        else                       APPEND(c("92", wrapped));
    }

    APPEND_CH(' ');

    if (showCwd) {
        char *cwd = procCwd(pid);
        APPEND(c("35", shquote(cwd)));
        APPEND(c("2", " % "));
        free(cwd);
    }

    char **argv;
    int argc = readCmdline(pid, &argv);
    if (argc == 0) {
        freeArgv(argv, argc);
        char *comm = readComm(pid);
        if (comm[0] == 0) { free(comm); free(sb); return; }
        char br[300];
        snprintf(br, sizeof br, "[%s]", comm);
        APPEND(c("2", br));
        free(comm);
    } else {
        char *cmd; // shquote returns pool buffer; copy before next shquote call
        if (fullPath) {
            char *exe = readExe(pid);
            if (exe[0] != 0) cmd = strdup(shquote(exe));
            else             cmd = strdup(shquote(argv[0]));
            free(exe);
        } else {
            cmd = strdup(shquote(argv[0]));
        }
        APPEND(c("96", cmd));
        free(cmd);
        if (showArgs && argc > 1) {
            for (int i = 1; i < argc; i++) {
                APPEND_CH(' ');
                APPEND(c("2", shquote(argv[i])));
            }
        }
    }
    freeArgv(argv, argc);

    if (showEnv) {
        char **env;
        int envc = readEnviron(pid, &env);
        APPEND("\n  ");
        for (int i = 0; i < envc; i++) {
            APPEND_CH(' ');
            const char *e = env[i];
            const char *eq = strchr(e, '=');
            if (eq) {
                // shquote(key)+"="+shquote(val) — copy first part before reuse.
                size_t klen = (size_t)(eq - e);
                char *key = malloc(klen + 1);
                memcpy(key, e, klen);
                key[klen] = 0;
                char *qk = strdup(shquote(key));
                const char *qv = shquote(eq + 1);
                size_t need = strlen(qk) + 1 + strlen(qv) + 1;
                char *joined = malloc(need);
                snprintf(joined, need, "%s=%s", qk, qv);
                APPEND(c("2", joined));
                free(joined);
                free(qk);
                free(key);
            } else {
                APPEND(c("2", shquote(e)));
            }
        }
        freeArgv(env, envc);
    }

    fprintf(out, "%s\n", sb);
#undef APPEND
#undef APPEND_CH
    free(sb);
}

static void buildExecedLine(const pidEntry *ent, int32_t pid) {
    char indent[1024];
    indentStr(ent->depth, indent, sizeof indent);
    char pidstr[16];
    snprintf(pidstr, sizeof pidstr, "%d", (int)pid);
    // fmt.Fprintln(out, line) — Println adds the trailing newline.
    char a[64], b[64];
    snprintf(a, sizeof a, "%s", c("33", pidstr));
    snprintf(b, sizeof b, "%s", c("31", "-"));
    fprintf(out, "%s%s%s %s execed\n",
            indent, a, b,
            c("2", shquote(ent->cmdline ? ent->cmdline : "")));
}

// ─── Event handlers ───────────────────────────────────────────────────────────

static void handleExec(const uint8_t *data, size_t len, uint64_t tsNs) {
    if (len < 8) return;
    int32_t pid = (int32_t)le32(data);

    int d = pidDepth(pid);
    if (d < 0) return;

    bool created;
    pidEntry *ent = piddb_get(pid, &created);
    bool exists = !created;

    if (showExit && exists && ent->cmdline && ent->cmdline[0] != 0) {
        buildExecedLine(ent, pid);
    }

    ent->depth   = d;
    ent->startNs = tsNs;
    free(ent->cmdline);
    ent->cmdline = readFirstArg(pid);

    printExec(pid, d, tsNs);
}

static void handleExit(const uint8_t *data, size_t len, uint64_t tsNs) {
    if (len < 24) return;
    int32_t  pid      = (int32_t)le32(data);
    uint32_t exitCode = le32(data + 8);

    pidEntry *ent = piddb_find(pid);
    bool ok = ent != NULL;

    // Snapshot before delete (Go deletes then uses the saved *pidEntry).
    pidEntry saved;
    char *savedCmd = NULL;
    if (ok) {
        saved = *ent;
        savedCmd = ent->cmdline ? strdup(ent->cmdline) : NULL;
        piddb_delete(pid);
    }

    if (!ok || !showExit) { free(savedCmd); return; }

    char indent[1024];
    indentStr(saved.depth, indent, sizeof indent);
    double elapsed = (double)(tsNs - saved.startNs) / 1e9;

    char exitStr[64];
    if ((exitCode & 0x7f) == 0) { // WIFEXITED
        int code = (int)((exitCode >> 8) & 0xff);
        if (code == 0) {
            snprintf(exitStr, sizeof exitStr, "%s", c("32", "status=0"));
        } else {
            char t[32];
            snprintf(t, sizeof t, "status=%d", code);
            snprintf(exitStr, sizeof exitStr, "%s", c("31", t));
        }
    } else { // signaled
        char t[32];
        snprintf(t, sizeof t, "signal=%s", sigName((int)(exitCode & 0x7f)));
        snprintf(exitStr, sizeof exitStr, "%s", c("91", t));
    }

    char pidstr[16];
    snprintf(pidstr, sizeof pidstr, "%d", (int)pid);
    char timebuf[32];
    snprintf(timebuf, sizeof timebuf, "time=%.3fs", elapsed);

    char colPid[64], colDash[64], colTime[64];
    snprintf(colPid,  sizeof colPid,  "%s", c("33", pidstr));
    snprintf(colDash, sizeof colDash, "%s", c("31", "-"));
    snprintf(colTime, sizeof colTime, "%s", c("36", timebuf));

    fprintf(out, "%s%s%s %s exited %s %s\n",
            indent, colPid, colDash,
            c("2", shquote(savedCmd ? savedCmd : "")),
            exitStr, colTime);

    free(savedCmd);
}

// ─── Netlink helpers ──────────────────────────────────────────────────────────

static int sendMcastOp(int fd, uint32_t op) {
    uint8_t buf[NLMSG_HDR_SIZE + CN_MSG_SIZE + 4];
    memset(buf, 0, sizeof buf);

    uint32_t total = (uint32_t)sizeof buf;
    put32(buf + 0, total);
    put16(buf + 4, NLMSG_DONE);
    put16(buf + 6, 0);
    put32(buf + 8, 0);
    put32(buf + 12, (uint32_t)getpid());

    put32(buf + 16, CN_IDX_PROC);
    put32(buf + 20, CN_VAL_PROC);
    put32(buf + 24, 0);
    put32(buf + 28, 0);
    put16(buf + 32, 4);
    put16(buf + 34, 0);

    put32(buf + 36, op);

    struct sockaddr_nl to;
    memset(&to, 0, sizeof to);
    to.nl_family = AF_NETLINK;
    ssize_t n = sendto(fd, buf, sizeof buf, 0,
                       (struct sockaddr *)&to, sizeof to);
    return n < 0 ? -1 : 0;
}

// dispatchNlMsg walks the recv buffer like syscall.ParseNetlinkMessage:
// for each nlmsghdr (len>=16, NLMSG_OK), data = buf+NLMSG_HDRLEN, advance
// by NLMSG_ALIGN(nlmsg_len).
//
// NOTE: like the Go original (dispatchNlMsg), the message *type* is never
// inspected — only the cn_msg idx/val gate validity. The kernel proc
// connector tags its event messages with nlmsg_type == NLMSG_DONE (3), so
// filtering DONE out here would silently drop every exec/exit event.
static void dispatchNlMsg(const uint8_t *data, size_t total) {
    size_t off = 0;
    while (total - off >= NLMSG_HDR_SIZE) {
        uint32_t nlmsg_len = le32(data + off);
        // NLMSG_OK: len >= hdr && len <= remaining.
        if (nlmsg_len < NLMSG_HDR_SIZE || nlmsg_len > total - off) break;

        const uint8_t *d = data + off + NLMSG_HDR_SIZE;
        size_t dlen = nlmsg_len - NLMSG_HDR_SIZE;

        if (dlen >= (size_t)(CN_MSG_SIZE + PROC_EVT_HDR)) {
            uint32_t idx = le32(d + 0);
            uint32_t val = le32(d + 4);
            if (idx == CN_IDX_PROC && val == CN_VAL_PROC) {
                uint32_t what = le32(d + CN_MSG_SIZE);
                uint64_t tsNs = le64(d + CN_MSG_SIZE + 8);
                const uint8_t *ev = d + CN_MSG_SIZE + PROC_EVT_HDR;
                size_t evlen = dlen - (CN_MSG_SIZE + PROC_EVT_HDR);
                if (what == PROC_EVENT_EXEC)
                    handleExec(ev, evlen, tsNs);
                else if (what == PROC_EVENT_EXIT)
                    handleExit(ev, evlen, tsNs);
            }
        }

        size_t adv = NLMSG_ALIGN(nlmsg_len);
        if (adv == 0 || adv > total - off) break;
        off += adv;
    }
}

// ─── CMD-mode child reaping ───────────────────────────────────────────────────

static int      g_fd = -1;
static pid_t    g_child;
static volatile sig_atomic_t g_childExited;

static void on_child(int s) {
    (void)s;
    int st;
    pid_t r;
    while ((r = waitpid(-1, &st, WNOHANG)) > 0) {
        if (r == g_child) g_childExited = 1;
    }
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
    fprintf(e, "\n  %s%s🔍 proc-trace-exec%s %s%s%s — system-wide exec() tracer for Linux\n\n",
            bold, cyan, reset, dim, tracep_version, reset);
    fprintf(e, "  %sUsage:%s\n", bold, reset);
    fprintf(e, "    proc-trace-exec %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n",
            dim, reset, yellow, reset);
    fprintf(e, "  %sFlags:%s\n", bold, reset);
    fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n",
            yellow, reset, dim, reset);
    fprintf(e, "    📁  %s-d%s          print cwd of each process\n", yellow, reset);
    fprintf(e, "    🌿  %s-e%s          print environment variables\n", yellow, reset);
    fprintf(e, "    ⬜  %s-f%s          flat output %s(no indentation)%s\n",
            yellow, reset, dim, reset);
    fprintf(e, "    🔗  %s-l%s          print full executable path\n", yellow, reset);
    fprintf(e, "    📝  %s-o%s %sFILE%s      log output to FILE instead of stdout\n",
            yellow, reset, cyan, reset);
    fprintf(e, "    🎯  %s-p%s %sPID%s       trace descendants of PID %s(repeat or comma-separate for multiple)%s\n",
            yellow, reset, cyan, reset, dim, reset);
    fprintf(e, "    🤫  %s-q%s          suppress arguments\n", yellow, reset);
    fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset);
    fprintf(e, "    ⏱️   %s-t%s          show exit status + timing\n", yellow, reset);
    fprintf(e, "    👤  %s-u%s          print owning user\n", yellow, reset);
    fprintf(e, "\n  %sExamples:%s\n", bold, reset);
    fprintf(e, "    %s# trace a command and all its children%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-exec %s-ct%s sh -c %s'make'%s\n\n",
            green, reset, magenta, reset);
    fprintf(e, "    %s# watch all nginx worker processes%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-exec %s-p%s $(pgrep nginx | paste -sd,)\n\n",
            green, reset);
    fprintf(e, "    %s# log everything quietly to a file%s\n", dim, reset);
    fprintf(e, "    sudo proc-trace-exec %s-Qo%s /var/log/execs.log\n\n",
            green, reset);
    exit(1);
}

// ─── main ─────────────────────────────────────────────────────────────────────

int exec_main(int argc, char **argv) {
    out = stdout;

    char **cmdArgs = NULL;
    int    nCmdArgs = 0;
    const char *outFile = NULL;

    // args = os.Args[1:]
    int nargs = argc - 1;
    char **args = argv + 1;

    for (int i = 0; i < nargs; i++) {
        char *a = args[i];
        if (strlen(a) < 2 || a[0] != '-') {
            cmdArgs  = &args[i];
            nCmdArgs = nargs - i;
            break;
        }
        for (char *pch = a + 1; *pch; pch++) {
            char ch = *pch;
            switch (ch) {
            case 'c': colorForce = true; break;
            case 'd': showCwd    = true; break;
            case 'e': showEnv    = true; break;
            case 'f': flatMode   = true; break;
            case 'l': fullPath   = true; break;
            case 'q': showArgs   = false; break;
            case 'Q': showErrors = false; break;
            case 't': showExit   = true; break;
            case 'u': showUser   = true; break;
            case 'p': {
                if (i + 1 >= nargs) fatal("flag -p requires an argument");
                i++;
                char *dup = strdup(args[i]);
                char *save = NULL;
                for (char *s = strtok_r(dup, ",", &save); s;
                     s = strtok_r(NULL, ",", &save)) {
                    while (*s == ' ' || *s == '\t' || *s == '\n' ||
                           *s == '\r' || *s == '\v' || *s == '\f')
                        s++;
                    size_t L = strlen(s);
                    while (L && (s[L - 1] == ' ' || s[L - 1] == '\t' ||
                                 s[L - 1] == '\n' || s[L - 1] == '\r' ||
                                 s[L - 1] == '\v' || s[L - 1] == '\f'))
                        s[--L] = 0;
                    if (L == 0) continue;
                    char *end;
                    errno = 0;
                    long pid = strtol(s, &end, 10);
                    if (end == s || *end != 0 || errno != 0 || pid <= 0)
                        fatalf("-p: invalid PID: %s", s);
                    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
                        fatalf("-p %d: no such process", (int)pid);
                    if (nWatchPIDs < (int)(sizeof watchPIDs / sizeof watchPIDs[0]))
                        watchPIDs[nWatchPIDs++] = (int32_t)pid;
                }
                free(dup);
                break;
            }
            case 'o':
                if (i + 1 >= nargs) fatal("flag -o requires an argument");
                i++;
                outFile = args[i];
                break;
            case 'h':
                usage();
                break;
            default:
                fatalf("unknown flag -%c", ch);
            }
        }
    }

    if (nWatchPIDs == 0) {
        watchPIDs[0] = 1; // default: global mode (trace everything)
        nWatchPIDs   = 1;
    }

    if (outFile && outFile[0] != 0) {
        FILE *f = fopen(outFile, "a");
        if (!f) fatalf("open %s: %s", outFile, strerror(errno));
        out = f;
    }

    // Auto-detect color: on when out is a tty and NO_COLOR is unset.
    if (colorForce) {
        colorMode = true;
    } else if (getenv("NO_COLOR") == NULL) {
        colorMode = is_terminal(out);
    }

    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR_PROTO);
    if (fd < 0) fatalf("socket: %s", strerror(errno));
    g_fd = fd;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid    = (uint32_t)getpid();
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0)
        fatalf("bind: %s", strerror(errno));

    if (sendMcastOp(fd, PROC_CN_MCAST_LISTEN) != 0)
        fatalf("subscribe: %s", strerror(errno));

    // CMD mode: fork the command and trace only its subtree.
    if (nCmdArgs > 0) {
        nWatchPIDs   = 1;
        watchPIDs[0] = (int32_t)getpid();

        struct sigaction act;
        memset(&act, 0, sizeof act);
        act.sa_handler = on_child;
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_RESTART;
        sigaction(SIGCHLD, &act, NULL);

        pid_t pid = fork();
        if (pid < 0)
            fatalf("exec %s: %s", cmdArgs[0], strerror(errno));
        if (pid == 0) {
            // Child: stdin/stdout/stderr inherited (matches cmd.Std* = os.Std*).
            char **cargv = malloc((size_t)(nCmdArgs + 1) * sizeof *cargv);
            for (int k = 0; k < nCmdArgs; k++) cargv[k] = cmdArgs[k];
            cargv[nCmdArgs] = NULL;
            execvp(cargv[0], cargv);
            // exec.Command/Start failure → fatalf("exec %s: %v").
            fprintf(stderr, "proc-trace-exec: exec %s: %s\n",
                    cmdArgs[0], strerror(errno));
            _exit(1);
        }
        g_child = pid;
    }

    // Event loop. recvfrom into a 64 KiB buffer, dispatch, repeat. In CMD
    // mode, the SIGCHLD handler flags exit; on the next loop turn (or right
    // away if already flagged) we IGNORE and exit(0) — matching the Go
    // goroutine that does cmd.Wait then sendMcastOp(IGNORE)+os.Exit(0).
    uint8_t buf[65536];
    for (;;) {
        if (g_childExited) {
            sendMcastOp(g_fd, PROC_CN_MCAST_IGNORE);
            exit(0);
        }
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue; // interrupted by SIGCHLD; re-check
            fatalf("recvfrom: %s", strerror(errno));
        }
        dispatchNlMsg(buf, (size_t)n);
    }
}

#else // ── non-Linux stub (port of exec_other.go) ────────────────────────────

int exec_main(int argc, char **argv) {
    (void)argc;
    (void)argv;
#if defined(__APPLE__)
    const char *os = "darwin";
#elif defined(__FreeBSD__)
    const char *os = "freebsd";
#elif defined(__OpenBSD__)
    const char *os = "openbsd";
#elif defined(__NetBSD__)
    const char *os = "netbsd";
#else
    const char *os = "unknown";
#endif
    fprintf(stderr,
            "tracep exec: exec() tracing is only supported on Linux (this is %s).\n"
            "Only `tracep ca` and `tracep dns` run on %s.\n",
            os, os);
    return 1;
}

#endif
