// dns — watch DNS queries made by every process (port of internal/dnstrace).
//
// Opens the platform packet-capture device (Linux AF_PACKET / macOS
// /dev/bpf), parses DNS on the wire, matches each response to its request
// to compute latency, and attributes the query to the owning process via
// /proc (Linux only — off Linux there is no portable socket→PID map, so
// pid 0 / name "?" is shown, exactly like the Go version).
#define _GNU_SOURCE
#include "common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// ── CLI state ────────────────────────────────────────────────────────────────

static bool  fJSON, fQuiet, fQQuiet, fFlat, fColor, fTime;
static char *fDomain = "";
static FILE *out;
static bool  use_color;

#define MAX_SET 64
static char *name_set[MAX_SET]; static int name_n;
static char *type_set[MAX_SET]; static int type_n;     // uppercased
static int   pid_set[MAX_SET];  static int pid_n;

// ── helpers ──────────────────────────────────────────────────────────────────

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("tracep dns: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}
static void log_err(const char *fmt, ...) {
    if (fQQuiet) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void split_set(const char *s, char **set, int *n, bool upper) {
    char *dup = strdup(s ? s : ""), *save = NULL;
    for (char *t = strtok_r(dup, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        while (*t == ' ' || *t == '\t') t++;
        size_t L = strlen(t);
        while (L && (t[L-1] == ' ' || t[L-1] == '\t')) t[--L] = 0;
        if (!L || *n >= MAX_SET) continue;
        char *v = strdup(t);
        if (upper) for (char *p = v; *p; p++) *p = toupper((unsigned char)*p);
        set[(*n)++] = v;
    }
    free(dup);
}
static void parse_pids(const char *s) {
    char *dup = strdup(s ? s : ""), *save = NULL;
    for (char *t = strtok_r(dup, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        char *e; long v = strtol(t, &e, 10);
        if (e != t && pid_n < MAX_SET) pid_set[pid_n++] = (int)v;
    }
    free(dup);
}
static bool in_str_set(char **set, int n, const char *v) {
    for (int i = 0; i < n; i++) if (!strcmp(set[i], v)) return true;
    return false;
}
static bool in_pid_set(int v) {
    for (int i = 0; i < pid_n; i++) if (pid_set[i] == v) return true;
    return false;
}
static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

// ── DNS wire-format parsing (mirrors dns.go) ─────────────────────────────────

#define MAX_ANS 16
typedef struct {
    uint16_t id, flags, qtype;
    char     question[256];
    char    *answers[MAX_ANS];
    int      ans_n;
} dns_msg;

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static int read_name(const uint8_t *d, int len, int off, char *dst, int dstcap) {
    int w = 0, orig = -1;
    if (dst && dstcap) dst[0] = 0;
    for (;;) {
        if (off >= len) return -1;
        int l = d[off];
        if (l == 0) { off++; if (orig != -1) off = orig; return off; }
        else if ((l & 0xC0) == 0xC0) {
            if (off + 2 > len) return -1;
            if (orig == -1) orig = off + 2;
            off = be16(d + off) & 0x3FFF;
        } else if ((l & 0xC0) == 0) {
            off++;
            if (off + l > len) return -1;
            if (dst) {
                if (w && w < dstcap - 1) dst[w++] = '.';
                for (int i = 0; i < l && w < dstcap - 1; i++) dst[w++] = d[off + i];
                dst[w] = 0;
            }
            off += l;
        } else return -1;
    }
}
static void add_answer(dns_msg *m, const char *prefix, const char *val) {
    if (m->ans_n >= MAX_ANS) return;
    char buf[300];
    snprintf(buf, sizeof buf, "%s%s", prefix ? prefix : "", val);
    m->answers[m->ans_n++] = strdup(buf);
}
static void free_msg(dns_msg *m) {
    for (int i = 0; i < m->ans_n; i++) free(m->answers[i]);
    m->ans_n = 0;
}
static bool parse_dns(const uint8_t *d, int len, dns_msg *m) {
    if (len < 12) return false;
    memset(m, 0, sizeof *m);
    m->id = be16(d); m->flags = be16(d + 2);
    int qd = be16(d + 4), an = be16(d + 6), off = 12;
    for (int i = 0; i < qd; i++) {
        char name[256];
        int n = read_name(d, len, off, name, sizeof name);
        if (n < 0) return false;
        off = n;
        if (off + 4 > len) return false;
        uint16_t qt = be16(d + off);
        off += 4;
        if (i == 0) { snprintf(m->question, sizeof m->question, "%s", name); m->qtype = qt; }
    }
    for (int i = 0; i < an; i++) {
        int n = read_name(d, len, off, NULL, 0);
        if (n < 0) break;
        off = n;
        if (off + 10 > len) break;
        uint16_t rtype = be16(d + off);
        off += 8;
        int rdlen = be16(d + off);
        off += 2;
        if (off + rdlen > len) break;
        int rdoff = off;
        const uint8_t *rd = d + off;
        off += rdlen;
        char nm[256], ip[INET6_ADDRSTRLEN];
        switch (rtype) {
        case 1:  if (rdlen == 4  && inet_ntop(AF_INET,  rd, ip, sizeof ip)) add_answer(m, "", ip); break;
        case 28: if (rdlen == 16 && inet_ntop(AF_INET6, rd, ip, sizeof ip)) add_answer(m, "", ip); break;
        case 5:  if (read_name(d, len, rdoff,   nm, sizeof nm) >= 0) add_answer(m, "CNAME:", nm); break;
        case 2:  if (read_name(d, len, rdoff,   nm, sizeof nm) >= 0) add_answer(m, "NS:", nm);    break;
        case 12: if (read_name(d, len, rdoff,   nm, sizeof nm) >= 0) add_answer(m, "", nm);       break;
        case 15: if (rdlen > 2 && read_name(d, len, rdoff+2, nm, sizeof nm) >= 0) add_answer(m, "MX:", nm);  break;
        case 33: if (rdlen > 6 && read_name(d, len, rdoff+6, nm, sizeof nm) >= 0) add_answer(m, "SRV:", nm); break;
        case 16: { int p = 0; while (p < rdlen) { int sl = rd[p++]; if (p+sl > rdlen) break;
                   char t[300]; int c = sl < (int)sizeof t - 1 ? sl : (int)sizeof t - 1;
                   memcpy(t, rd+p, c); t[c]=0; add_answer(m, "", t); p += sl; } break; }
        }
    }
    return true;
}
static const char *qtype_str(uint16_t t) {
    switch (t) {
    case 1: return "A";   case 2: return "NS";  case 5: return "CNAME"; case 6: return "SOA";
    case 12: return "PTR";case 15: return "MX"; case 16: return "TXT";  case 28: return "AAAA";
    case 33: return "SRV";case 255: return "ANY";
    }
    static char b[16]; snprintf(b, sizeof b, "TYPE%u", t); return b;
}
static const char *rcode_str(uint16_t r) {
    switch (r & 0xF) {
    case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";case 4: return "NOTIMP";  case 5: return "REFUSED";
    }
    static char b[16]; snprintf(b, sizeof b, "RCODE%u", r & 0xF); return b;
}

// ── packet → DNS (mirrors packet.go) ─────────────────────────────────────────

static bool parse_packet(const uint8_t *pkt, int len, dns_msg *m,
                         uint16_t *src, uint16_t *dst) {
    if (len < 14) return false;
    uint16_t eth = be16(pkt + 12);
    const uint8_t *ip; int iplen;
    if (eth == 0x0800) {
        ip = pkt + 14; iplen = len - 14;
        if (iplen < 20 || (ip[0] >> 4) != 4 || ip[9] != 17) return false;
        int ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || iplen < ihl + 8) return false;
        ip += ihl; iplen -= ihl;
    } else if (eth == 0x86DD) {
        ip = pkt + 14; iplen = len - 14;
        if (iplen < 40 || (ip[0] >> 4) != 6 || ip[6] != 17) return false;
        ip += 40; iplen -= 40;
    } else return false;
    if (iplen < 8) return false;
    *src = be16(ip); *dst = be16(ip + 2);
    if (*src != 53 && *dst != 53) return false;
    return parse_dns(ip + 8, iplen - 8, m);
}

// ── platform capture backend (capture_linux.go / capture_darwin.go) ──────────

typedef struct capture capture;
static capture *cap_open(char *errbuf, size_t errsz);
static int       cap_next(capture *c, const uint8_t **frame, int *len);
static void      cap_close(capture *c);

#if defined(__linux__)
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
struct capture { int fd; uint8_t buf[65536]; };
static capture *cap_open(char *errbuf, size_t errsz) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        snprintf(errbuf, errsz,
                 "socket: %s\nHint: run as root or: sudo setcap cap_net_raw+eip tracep",
                 strerror(errno));
        return NULL;
    }
    capture *c = calloc(1, sizeof *c);
    c->fd = fd;
    return c;
}
static int cap_next(capture *c, const uint8_t **frame, int *len) {
    ssize_t n = recv(c->fd, c->buf, sizeof c->buf, 0);
    if (n < 0) return -1;
    *frame = c->buf; *len = (int)n;
    return 0;
}
static void cap_close(capture *c) { if (c) { close(c->fd); free(c); } }

// Linux PID attribution: /proc/net/udp{,6} inode → /proc/<pid>/fd scan.
static long inode_for_port(uint16_t port, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512], want[8];
    snprintf(want, sizeof want, "%04X", port);
    if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
    long inode = -1;
    while (fgets(line, sizeof line, f)) {
        char local[128]; long ino;
        if (sscanf(line, " %*d %127s %*s %*s %*s %*s %*s %*s %*d %*d %ld", local, &ino) != 2)
            continue;
        char *colon = strrchr(local, ':');
        if (colon && strcasecmp(colon + 1, want) == 0) { inode = ino; break; }
    }
    fclose(f);
    return inode;
}
static void comm_for_pid(int pid, char *dst, int cap) {
    char path[64]; snprintf(path, sizeof path, "/proc/%d/comm", pid);
    snprintf(dst, cap, "?");
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(dst, cap, f)) dst[strcspn(dst, "\n")] = 0;
    fclose(f);
}
static int pid_for_udp_port(uint16_t port, char *name, int namecap) {
    long inode = inode_for_port(port, "/proc/net/udp");
    if (inode < 0) inode = inode_for_port(port, "/proc/net/udp6");
    snprintf(name, namecap, "?");
    if (inode < 0) return 0;
    char target[40];
    snprintf(target, sizeof target, "socket:[%ld]", inode);
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    struct dirent *de; int found = 0;
    while ((de = readdir(proc)) && !found) {
        char *e; long pid = strtol(de->d_name, &e, 10);
        if (*e) continue;
        char fddir[64]; snprintf(fddir, sizeof fddir, "/proc/%ld/fd", pid);
        DIR *fd = opendir(fddir);
        if (!fd) continue;
        struct dirent *fe;
        while ((fe = readdir(fd))) {
            char link[400], buf[64];
            snprintf(link, sizeof link, "%s/%s", fddir, fe->d_name);
            ssize_t r = readlink(link, buf, sizeof buf - 1);
            if (r < 0) continue;
            buf[r] = 0;
            if (!strcmp(buf, target)) { comm_for_pid((int)pid, name, namecap); found = (int)pid; break; }
        }
        closedir(fd);
    }
    closedir(proc);
    return found;
}

#elif defined(__APPLE__)
// macOS has no AF_PACKET. Use /dev/bpfN bound to a real Ethernet interface
// with immediate delivery, and walk the bpf_hdr-framed records out of each
// read(). No socket→PID map off Linux (proc_other.go) — pid 0, name "?".
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
struct capture {
    int fd;
    uint8_t *buf; int buflen;     // kernel bpf buffer
    uint8_t *rec; int reclen;     // unconsumed bytes from last read()
};
// Pick an up, non-loopback IPv4 interface (prefer en*) — pickInterface().
static int pick_iface(char *name, size_t cap) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return -1;
    char fallback[IFNAMSIZ] = "";
    int ok = -1;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        struct in_addr a = ((struct sockaddr_in *)p->ifa_addr)->sin_addr;
        uint32_t h = ntohl(a.s_addr);
        if (h == 0 || (h >> 24) == 127) continue;          // unspecified/loopback
        if (strncmp(p->ifa_name, "en", 2) == 0) {          // prefer Ethernet/Wi-Fi
            snprintf(name, cap, "%s", p->ifa_name); ok = 0; break;
        }
        if (!fallback[0]) snprintf(fallback, sizeof fallback, "%s", p->ifa_name);
    }
    freeifaddrs(ifa);
    if (ok != 0 && fallback[0]) { snprintf(name, cap, "%s", fallback); ok = 0; }
    return ok;
}
static capture *cap_open(char *errbuf, size_t errsz) {
    char iface[IFNAMSIZ];
    if (pick_iface(iface, sizeof iface) != 0) {
        snprintf(errbuf, errsz, "no up non-loopback IPv4 interface found");
        return NULL;
    }
    int fd = -1;
    for (int i = 0; i < 256; i++) {
        char dev[16]; snprintf(dev, sizeof dev, "/dev/bpf%d", i);
        fd = open(dev, O_RDONLY);
        if (fd >= 0) break;
    }
    if (fd < 0) { snprintf(errbuf, errsz, "open /dev/bpf*: %s\nHint: run with sudo", strerror(errno)); return NULL; }

    u_int blen = 32768;
    if (ioctl(fd, BIOCSBLEN, &blen) < 0) { snprintf(errbuf, errsz, "BIOCSBLEN: %s", strerror(errno)); close(fd); return NULL; }
    if (ioctl(fd, BIOCGBLEN, &blen) < 0) { snprintf(errbuf, errsz, "BIOCGBLEN: %s", strerror(errno)); close(fd); return NULL; }

    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) { snprintf(errbuf, errsz, "BIOCSETIF %s: %s", iface, strerror(errno)); close(fd); return NULL; }

    u_int one = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &one) < 0) { snprintf(errbuf, errsz, "BIOCIMMEDIATE: %s", strerror(errno)); close(fd); return NULL; }
    ioctl(fd, BIOCSHDRCMPLT, &one);          // best-effort

    u_int dlt = 0;
    if (ioctl(fd, BIOCGDLT, &dlt) < 0) { snprintf(errbuf, errsz, "BIOCGDLT: %s", strerror(errno)); close(fd); return NULL; }
    if (dlt != DLT_EN10MB) { snprintf(errbuf, errsz, "interface %s link type %u is not Ethernet (DLT_EN10MB); unsupported", iface, dlt); close(fd); return NULL; }

    capture *c = calloc(1, sizeof *c);
    c->fd = fd; c->buflen = blen; c->buf = malloc(blen);
    return c;
}
// Split the next bpf_hdr-framed record (BPF_WORDALIGN between records).
static int cap_next(capture *c, const uint8_t **frame, int *len) {
    for (;;) {
        if (c->rec && c->reclen >= (int)sizeof(struct bpf_hdr)) {
            struct bpf_hdr *bh = (struct bpf_hdr *)c->rec;
            int caplen = bh->bh_caplen, hdrlen = bh->bh_hdrlen;
            if (hdrlen >= (int)sizeof *bh && caplen >= 0 && hdrlen + caplen <= c->reclen) {
                *frame = c->rec + hdrlen; *len = caplen;
                int adv = BPF_WORDALIGN(hdrlen + caplen);
                if (adv >= c->reclen) { c->rec = NULL; c->reclen = 0; }
                else { c->rec += adv; c->reclen -= adv; }
                return 0;
            }
        }
        c->rec = NULL; c->reclen = 0;             // exhausted/malformed — resync
        ssize_t n = read(c->fd, c->buf, c->buflen);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n <= 0) continue;
        c->rec = c->buf; c->reclen = (int)n;
    }
}
static void cap_close(capture *c) { if (c) { close(c->fd); free(c->buf); free(c); } }

// macOS socket→PID via lsof — same approach as proc_darwin.go. One
// `lsof -nP -iUDP -F pcn` scan fills a port→(pid, name) map; subsequent
// lookups for any port within the 2-second TTL hit it for free. Non-root
// callers see only own-user sockets (lsof limitation).
typedef struct { int pid; char name[64]; } mac_pn;
static mac_pn mac_udp[65536];
static double mac_udp_born_ms;

static void mac_scan_udp(void) {
    memset(mac_udp, 0, sizeof mac_udp);
    FILE *p = popen("/usr/sbin/lsof -nP -iUDP -F pcn 2>/dev/null", "r");
    if (!p) return;
    int  cur_pid = 0;
    char cur_name[64] = "?";
    char line[1024];
    while (fgets(line, sizeof line, p)) {
        size_t L = strlen(line);
        while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        if (L < 2) continue;
        switch (line[0]) {
        case 'p': {
            long v = strtol(line + 1, NULL, 10);
            if (v > 0) cur_pid = (int)v;
            break;
        }
        case 'c':
            snprintf(cur_name, sizeof cur_name, "%s", line + 1);
            break;
        case 'n': {
            // "n*:54321" or "n127.0.0.1:5353" or "n[::]:5353" or "n*:*"
            const char *body = line + 1;
            const char *colon = strrchr(body, ':');
            if (!colon) break;
            const char *pstr = colon + 1;
            if (*pstr == '*') break;
            // Strip "->host:port" connected suffix.
            char buf[16];
            size_t pl = 0;
            for (; pstr[pl] && pstr[pl] != '-' && pl + 1 < sizeof buf; pl++)
                buf[pl] = pstr[pl];
            buf[pl] = 0;
            long port = strtol(buf, NULL, 10);
            if (port <= 0 || port > 65535) break;
            mac_udp[port].pid = cur_pid;
            snprintf(mac_udp[port].name, sizeof mac_udp[port].name, "%s", cur_name);
            break;
        }
        }
    }
    pclose(p);
}

static int pid_for_udp_port(uint16_t port, char *name, int namecap) {
    double t = now_ms();
    if (mac_udp_born_ms == 0 || t - mac_udp_born_ms > 2000.0) {
        mac_scan_udp();
        mac_udp_born_ms = t;
    }
    if (mac_udp[port].pid > 0) {
        snprintf(name, namecap, "%s", mac_udp[port].name);
        return mac_udp[port].pid;
    }
    snprintf(name, namecap, "?");
    return 0;
}
#else
struct capture { int unused; };
static capture *cap_open(char *errbuf, size_t errsz) {
    snprintf(errbuf, errsz, "dns capture is only supported on Linux and macOS");
    return NULL;
}
static int  cap_next(capture *c, const uint8_t **f, int *l) { (void)c;(void)f;(void)l; return -1; }
static void cap_close(capture *c) { (void)c; }
static int  pid_for_udp_port(uint16_t p, char *n, int c) { (void)p; snprintf(n,c,"?"); return 0; }
#endif

// ── proc cache (2 s TTL, port-keyed) — mirrors proc.go ───────────────────────

#define CACHE_TTL_MS 2000.0
typedef struct { int pid; char name[64]; double born; bool set; } cache_ent;
static cache_ent pcache[65536];

static int proc_lookup(uint16_t port, char *name, int namecap) {
    cache_ent *e = &pcache[port];
    double t = now_ms();
    if (e->set && t - e->born < CACHE_TTL_MS) { snprintf(name, namecap, "%s", e->name); return e->pid; }
    char nm[64];
    int pid = pid_for_udp_port(port, nm, sizeof nm);
    e->pid = pid; e->born = t; e->set = true;
    snprintf(e->name, sizeof e->name, "%s", nm);
    snprintf(name, namecap, "%s", nm);
    return pid;
}

// ── in-flight queries, keyed by transaction id ───────────────────────────────

typedef struct {
    bool   set;
    char   query[256];
    char   qtype[16];
    int    pid;
    char   name[64];
    double sent;
} pending_t;
static pending_t pending[65536];

// ── output (mirrors dns.go emit*) ────────────────────────────────────────────

static void json_escape(const char *s, char *o, int cap) {
    int w = 0;
    for (; *s && w < cap - 8; s++) {
        if (*s == '"' || *s == '\\') { o[w++] = '\\'; o[w++] = *s; }
        else if ((unsigned char)*s < 0x20) w += snprintf(o+w, cap-w, "\\u%04x", *s);
        else o[w++] = *s;
    }
    o[w] = 0;
}
static const char *trunc15(const char *s) {
    static char b[64];
    if (strlen(s) <= 15) { snprintf(b, sizeof b, "%s", s); return b; }
    snprintf(b, sizeof b, "%.14s\xe2\x80\xa6", s);   // 14 chars + "…"
    return b;
}
static void emit(const char *query, const char *qtype, int pid, const char *name,
                 const dns_msg *resp, double latency) {
    if (name_n && !in_str_set(name_set, name_n, name)) return;
    if (pid_n  && !in_pid_set(pid))                    return;
    if (type_n && !in_str_set(type_set, type_n, qtype))return;
    if (*fDomain && !strstr(query, fDomain))           return;

    const char *rcode = rcode_str(resp->flags & 0x0F);
    char ts[32] = "";
    if (fTime) { time_t now = time(NULL); struct tm tm; localtime_r(&now, &tm);
                 strftime(ts, sizeof ts, "%H:%M:%S", &tm); }

    if (fQuiet) { fprintf(out, "%s\n", query); fflush(out); return; }

    if (fJSON) {
        char eq[600], en[256];
        json_escape(query, eq, sizeof eq);
        json_escape(name,  en, sizeof en);
        fprintf(out, "{\"pid\":%d,\"name\":\"%s\",\"type\":\"%s\",\"query\":\"%s\",\"answers\":[",
                pid, en, qtype, eq);
        for (int i = 0; i < resp->ans_n; i++) {
            char ea[600]; json_escape(resp->answers[i], ea, sizeof ea);
            fprintf(out, "%s\"%s\"", i ? "," : "", ea);
        }
        fprintf(out, "],\"rcode\":\"%s\",\"latency_ms\":%.3f", rcode, latency);
        if (fTime) fprintf(out, ",\"ts\":\"%s\"", ts);
        fprintf(out, "}\n");
        fflush(out);
        return;
    }

    char pidbuf[16]; snprintf(pidbuf, sizeof pidbuf, "%d", pid);
    if (fTime) fprintf(out, "%s  ", clr(use_color, "36", ts));
    if (fFlat)
        fprintf(out, "%s  %s  %s  %s  ",
                clr(use_color, "33", pidbuf), clr(use_color, "96", name),
                clr(use_color, "35", qtype),  clr(use_color, "32", query));
    else
        fprintf(out, "%-7s  %-15s  %-5s  %-42s  ",
                clr(use_color, "33", pidbuf), clr(use_color, "96", trunc15(name)),
                clr(use_color, "35", qtype),  clr(use_color, "32", query));

    fprintf(out, "%s", clr(use_color, "90", "\xe2\x86\x92 "));   // dim "→ "
    if (!strcmp(rcode, "NOERROR")) {
        char joined[2048] = "";
        for (int i = 0; i < resp->ans_n; i++) {
            if (i) strncat(joined, " ", sizeof joined - strlen(joined) - 1);
            strncat(joined, resp->answers[i], sizeof joined - strlen(joined) - 1);
        }
        if (*joined) fprintf(out, "%s", clr(use_color, "34", joined));
    } else fprintf(out, "%s", clr(use_color, "31", rcode));
    char lat[32]; snprintf(lat, sizeof lat, "%.1fms", latency);
    fprintf(out, "  %s\n", clr(use_color, "90", lat));
    fflush(out);
}

// ── command spawn (`-- CMD`) + signals ───────────────────────────────────────

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }
static void on_alarm(int s) { (void)s; _exit(0); }
static void on_child(int s) {
    (void)s;
    int st; while (waitpid(-1, &st, WNOHANG) > 0) {}
    struct itimerval it = {{0,0},{0, 500000}};   // drain final responses 500ms
    setitimer(ITIMER_REAL, &it, NULL);
}

// ── help (port of dnstrace Main's fs.Usage) ──────────────────────────────────

static void usage(void) {
    bool C = fColor || (is_terminal(stderr) && !getenv("NO_COLOR"));
    const char *bold = C?"\033[1m":"", *cyan = C?"\033[36m":"", *yel = C?"\033[33m":"";
    const char *grn = C?"\033[32m":"", *dim = C?"\033[2m":"", *rst = C?"\033[0m":"";
    #define E(x) (C ? x " " : "")
    FILE *e = stderr;
    fprintf(e, "\n%s%sproc-trace-dns%s  %s(v%s)%s\n", bold, cyan, rst, dim, tracep_version, rst);
    fprintf(e, "%sWatch every DNS query your processes make, in real time.%s\n\n", dim, rst);
    fprintf(e, "%s%sUSAGE%s\n", bold, yel, rst);
    fprintf(e, "  tracep dns [flags] [-- CMD [args...]]\n\n");
    fprintf(e, "%s%s%sFLAGS%s\n", E("\xf0\x9f\x9a\xa9"), bold, yel, rst);
    fprintf(e, "  %s%s-c%s              %sforce ANSI color output%s\n", bold, cyan, rst, dim, rst);
    fprintf(e, "  %s%s-t%s              %sshow timestamp for each query%s\n", bold, cyan, rst, dim, rst);
    fprintf(e, "  %s%s-q%s              %squiet — print only queried hostnames%s\n", bold, cyan, rst, dim, rst);
    fprintf(e, "  %s%s-Q%s              %ssuppress error messages%s\n", bold, cyan, rst, dim, rst);
    fprintf(e, "  %s%s-f%s              %sflat output — no column alignment%s\n", bold, cyan, rst, dim, rst);
    fprintf(e, "  %s%s-j%s              %sJSON output (one object per line)%s\n", bold, cyan, rst, dim, rst);
    fprintf(e, "  %s%s-n%s %sNAME,...%s      only show queries from these process names\n", bold, cyan, rst, yel, rst);
    fprintf(e, "  %s%s-p%s %sPID,...%s       only show queries from these PIDs\n", bold, cyan, rst, yel, rst);
    fprintf(e, "  %s%s-d%s %sDOMAIN%s        only show queries matching this domain substring\n", bold, cyan, rst, yel, rst);
    fprintf(e, "  %s%s-T%s %sTYPE,...%s      only show these DNS record types (e.g. A,AAAA,MX)\n", bold, cyan, rst, yel, rst);
    fprintf(e, "  %s%s-o%s %sFILE%s          append output to FILE instead of stdout\n\n", bold, cyan, rst, yel, rst);
    fprintf(e, "%s%s%sEXAMPLES%s\n", E("\xf0\x9f\x92\xa1"), bold, yel, rst);
    #define EX(c,m) fprintf(e, "  %s%s%-52s%s%s# %s%s\n", bold, grn, c, rst, dim, m, rst)
    EX("sudo tracep dns",                             "system-wide, all processes");
    EX("sudo tracep dns -n curl,wget",                "filter by process name");
    EX("sudo tracep dns -p 1234,5678",                "filter by PID");
    EX("sudo tracep dns -d amazonaws.com",            "filter by domain substring");
    EX("sudo tracep dns -T A,AAAA",                   "only show A and AAAA records");
    EX("sudo tracep dns -j | jq .",                   "JSON output, pretty-printed");
    EX("sudo tracep dns -- curl https://example.com", "trace a single command");
    fprintf(e, "\n%s%sRequires root or CAP_NET_RAW (Linux) / sudo (macOS).%s\n\n", E("\xe2\x9a\xa0"), dim, rst);
    #undef E
    #undef EX
}

// ── main ─────────────────────────────────────────────────────────────────────

int dns_main(int argc, char **argv) {
    out = stdout;
    char *fOutput = "";

    // Manual flag scan (Go's flag package semantics: "-x", "-x val",
    // "-x=val"; "--" or first non-flag ends options → spawn command).
    int i = 1;
    for (; i < argc; i++) {
        char *a = argv[i];
        if (a[0] != '-' || a[1] == 0) break;          // non-flag → CMD
        if (!strcmp(a, "--")) { i++; break; }         // explicit terminator
        char *eq = strchr(a, '=');
        char ch = a[1];
        char *val = NULL;
        if (eq) val = eq + 1;
        switch (ch) {
        case 'c': fColor = true; break;
        case 'f': fFlat = true; break;
        case 'j': fJSON = true; break;
        case 'q': fQuiet = true; break;
        case 'Q': fQQuiet = true; break;
        case 't': fTime = true; break;
        case 'h': usage(); return 0;
        case 'n': case 'p': case 'd': case 'o': case 'T':
            if (!val) { if (i + 1 >= argc) die("flag -%c requires an argument", ch); val = argv[++i]; }
            if (ch == 'n') split_set(val, name_set, &name_n, false);
            else if (ch == 'p') parse_pids(val);
            else if (ch == 'd') fDomain = val;
            else if (ch == 'o') fOutput = val;
            else if (ch == 'T') split_set(val, type_set, &type_n, true);
            break;
        default: die("flag provided but not defined: -%c", ch);
        }
    }

    use_color = fColor || (is_terminal(stdout) && !getenv("NO_COLOR"));
    if (*fOutput) {
        out = fopen(fOutput, "a");
        if (!out) die("open output file: %s", strerror(errno));
        if (!fColor) use_color = false;
    }

    char errbuf[256];
    capture *cap = cap_open(errbuf, sizeof errbuf);
    if (!cap) die("%s", errbuf);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    // `-- CMD`: run it, filter to its PID, exit shortly after it ends.
    if (i < argc) {
        signal(SIGCHLD, on_child);
        signal(SIGALRM, on_alarm);
        pid_t pid = fork();
        if (pid < 0) die("start command: %s", strerror(errno));
        if (pid == 0) { execvp(argv[i], &argv[i]); _exit(127); }
        if (pid_n < MAX_SET) pid_set[pid_n++] = (int)pid;
    }

    while (!stop) {
        const uint8_t *frame; int n;
        if (cap_next(cap, &frame, &n) < 0) {
            if (errno == EINTR) continue;
            log_err("capture: %s", strerror(errno));
            continue;
        }
        dns_msg m; uint16_t src, dst;
        if (!parse_packet(frame, n, &m, &src, &dst)) continue;
        bool is_query = (m.flags & 0x8000) == 0;
        if (is_query && dst == 53) {
            pending_t *p = &pending[m.id];
            p->set = true;
            snprintf(p->query, sizeof p->query, "%s", m.question);
            snprintf(p->qtype, sizeof p->qtype, "%s", qtype_str(m.qtype));
            p->pid = proc_lookup(src, p->name, sizeof p->name);
            p->sent = now_ms();
        } else if (!is_query && src == 53) {
            pending_t *p = &pending[m.id];
            if (p->set) { p->set = false; emit(p->query, p->qtype, p->pid, p->name, &m, now_ms() - p->sent); }
        }
        free_msg(&m);
    }
    cap_close(cap);
    return 0;
}
