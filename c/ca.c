// ca — fetch a host's TLS CA chain (port of internal/cafetch/ca.go).
//
// Connects to <hostname>:<port> over TLS, prints the presented certificate
// chain, optionally chases the AIA caIssuers URL of the topmost cert to
// recover the root, and writes the CA certificate(s) as PEM. Cross-platform
// (Linux + macOS) — the one tracer that depends on OpenSSL rather than the
// Go stdlib.
#define _GNU_SOURCE
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// ── CLI state ────────────────────────────────────────────────────────────────

static int   fPort      = 443;
static char *fOutput    = "";
static bool  fFetchRoot = false;
static bool  fInsecure  = false;
static bool  fAll       = false;
static int   fTimeout   = 10;
static bool  fShowVer   = false;

// flag.PrintDefaults() rendering for this flag set. Go prints flags in
// lexicographic order, one-tab-indented description lines, and omits the
// "(default ...)" suffix for bool flags whose default is false and for the
// empty-string default of -o.
static void print_defaults(void) {
    FILE *e = stderr;
    fprintf(e, "  -all\n    \tSave full chain including leaf certificate\n");
    fprintf(e, "  -fetch-root\n    \tFetch root CA via AIA URL\n");
    fprintf(e, "  -insecure\n    \tSkip TLS certificate verification\n");
    fprintf(e, "  -o string\n    \tOutput file (default: <hostname>-ca.pem, use - for stdout)\n");
    fprintf(e, "  -port int\n    \tTLS port to connect to (default 443)\n");
    fprintf(e, "  -timeout int\n    \tConnection timeout in seconds (default 10)\n");
    fprintf(e, "  -version\n    \tPrint version and exit\n");
}

// ── flag parsing with positional permutation (mirrors ca.go's loop) ──────────
//
// Go's flag pkg stops at the first non-flag arg; ca.go re-runs Parse over the
// remaining args, collecting positionals, so flags may appear before OR after
// positionals (e.g. `tracep ca github.com -o -`). We replicate that by a
// single left-to-right scan that accepts a flag anywhere and accumulates the
// rest as positionals — equivalent outcome for this flag set.

static void usage_err(void) {
    fprintf(stderr, "usage: tracep ca [flags] <hostname> [port]\n");
    print_defaults();
    exit(1);
}

// Match a single-dash long flag. Returns: 0 = not this flag, 1 = matched and
// value consumed (sets *valp), 2 = matched bool (no value).
static int match_flag(char **argv, int argc, int *ip, const char *name,
                      bool is_bool, char **valp) {
    char *a = argv[*ip];
    if (a[0] != '-') return 0;
    const char *body = a + 1;
    if (body[0] == '-') body++;            // tolerate `--flag` as well
    size_t nl = strlen(name);
    if (strncmp(body, name, nl) != 0) return 0;
    char after = body[nl];
    if (after == 0) {
        if (is_bool) { *valp = NULL; return 2; }
        if (*ip + 1 >= argc) { fprintf(stderr, "flag needs an argument: -%s\n", name); exit(1); }
        *valp = argv[++(*ip)];
        return 1;
    }
    if (after == '=') {
        *valp = (char *)body + nl + 1;
        return is_bool ? 2 : 1;
    }
    return 0;
}

static bool parse_bool(const char *v) {
    // Go's flag bool: empty/absent value (-flag form) is true; -flag=x parses
    // x as a Go bool literal.
    if (!v || !*v) return true;
    if (!strcmp(v, "1") || !strcmp(v, "t") || !strcmp(v, "T") ||
        !strcmp(v, "true") || !strcmp(v, "TRUE") || !strcmp(v, "True"))
        return true;
    if (!strcmp(v, "0") || !strcmp(v, "f") || !strcmp(v, "F") ||
        !strcmp(v, "false") || !strcmp(v, "FALSE") || !strcmp(v, "False"))
        return false;
    fprintf(stderr, "invalid boolean value %s for flag\n", v);
    exit(1);
}

// ── cert helpers (mirror certRole / shortCN) ─────────────────────────────────

static const char *cert_role(X509 *c, int idx) {
    int is_ca = (X509_check_ca(c) == 1);
    if (idx == 0 && !is_ca) return "leaf";
    if (is_ca && X509_check_issued(c, c) == X509_V_OK) return "root CA";
    if (is_ca) return "intermediate CA";
    return "unknown";
}

// shortCN: CN longer than 38 → first 35 + "...". Operates on bytes, like Go's
// string slicing of cert.Subject.CommonName.
static const char *short_cn(const char *cn) {
    static char pool[4][64];
    static int slot;
    char *b = pool[slot++ & 3];
    size_t L = strlen(cn);
    if (L > 38) snprintf(b, 64, "%.35s...", cn);
    else        snprintf(b, 64, "%s", cn);
    return b;
}

// X509 subject/issuer CommonName (first CN RDN), "" if none — matches Go's
// pkix.Name.CommonName behaviour.
static const char *name_cn(X509_NAME *nm, char *buf, size_t cap) {
    buf[0] = 0;
    if (!nm) return buf;
    int i = X509_NAME_get_index_by_NID(nm, NID_commonName, -1);
    if (i < 0) return buf;
    X509_NAME_ENTRY *e = X509_NAME_get_entry(nm, i);
    ASN1_STRING *s = X509_NAME_ENTRY_get_data(e);
    unsigned char *utf8 = NULL;
    int n = ASN1_STRING_to_UTF8(&utf8, s);
    if (n >= 0 && utf8) {
        size_t k = (size_t)n < cap - 1 ? (size_t)n : cap - 1;
        memcpy(buf, utf8, k);
        buf[k] = 0;
    }
    OPENSSL_free(utf8);
    return buf;
}

// notAfter formatted "2006-01-02" (Go's reference layout → "%Y-%m-%d").
static const char *not_after(X509 *c, char *buf, size_t cap) {
    const ASN1_TIME *t = X509_get0_notAfter(c);
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    if (t && ASN1_TIME_to_tm(t, &tm))
        strftime(buf, cap, "%Y-%m-%d", &tm);
    else
        snprintf(buf, cap, "?");
    return buf;
}

// First AIA caIssuers URL, or NULL. Mirrors x509.Certificate.IssuingCertificateURL[0].
static char *aia_ca_issuer(X509 *c) {
    AUTHORITY_INFO_ACCESS *aia =
        X509_get_ext_d2i(c, NID_info_access, NULL, NULL);
    if (!aia) return NULL;
    char *url = NULL;
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers) continue;
        if (ad->location->type != GEN_URI) continue;
        ASN1_IA5STRING *u = ad->location->d.uniformResourceIdentifier;
        const unsigned char *p = ASN1_STRING_get0_data(u);
        int n = ASN1_STRING_length(u);
        if (p && n > 0) { url = strndup((const char *)p, (size_t)n); break; }
    }
    AUTHORITY_INFO_ACCESS_free(aia);
    return url;
}

// ── OpenSSL error → message (for "error: %v" / "warning: ... %v") ────────────

static const char *ssl_errstr(void) {
    static char b[256];
    unsigned long e = ERR_get_error();
    if (e == 0) { snprintf(b, sizeof b, "TLS handshake failed"); return b; }
    ERR_error_string_n(e, b, sizeof b);
    return b;
}

// ── timed TCP connect (non-blocking + select; never hangs) ───────────────────

static int dial(const char *host, int port, int timeout_s, char *err, size_t errsz) {
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        // Mirror the shape of Go's dial error closely enough to be useful;
        // exact text differs (gai_strerror vs net pkg) — see NOTE below.
        snprintf(err, errsz, "dial tcp: lookup %s: %s", host, gai_strerror(gai));
        return -1;
    }

    struct timeval deadline_tv;
    gettimeofday(&deadline_tv, NULL);
    time_t deadline = deadline_tv.tv_sec + timeout_s;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) goto connected;
        if (errno != EINPROGRESS) { close(fd); fd = -1; continue; }

        for (;;) {
            struct timeval now;
            gettimeofday(&now, NULL);
            long remain = (long)(deadline - now.tv_sec);
            if (remain <= 0) {
                snprintf(err, errsz,
                         "dial tcp %s:%d: i/o timeout", host, port);
                close(fd);
                freeaddrinfo(res);
                return -1;
            }
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(fd, &wf);
            struct timeval tv = { remain, 0 };
            int s = select(fd + 1, NULL, &wf, NULL, &tv);
            if (s < 0) {
                if (errno == EINTR) continue;
                snprintf(err, errsz, "dial tcp %s:%d: %s", host, port, strerror(errno));
                close(fd); fd = -1; break;
            }
            if (s == 0) {
                snprintf(err, errsz, "dial tcp %s:%d: i/o timeout", host, port);
                close(fd);
                freeaddrinfo(res);
                return -1;
            }
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
            if (soerr == 0) goto connected;
            snprintf(err, errsz, "dial tcp %s:%d: %s", host, port, strerror(soerr));
            close(fd); fd = -1;
            break;
        }
        continue;

    connected:
        fcntl(fd, F_SETFL, fl);             // back to blocking for TLS
        freeaddrinfo(res);
        return fd;
    }

    freeaddrinfo(res);
    if (fd < 0 && err[0] == 0)
        snprintf(err, errsz, "dial tcp %s:%d: connect failed", host, port);
    return -1;
}

// ── minimal HTTP/HTTPS GET (dependency-free, follows up to 10 redirects) ─────
//
// NOTE: ca.go uses net/http (Go's default client follows up to 10 redirects).
// To avoid adding libcurl we implement a tiny HTTP/1.1 GET here, reusing the
// connect + OpenSSL machinery for https. Only what fetchDERCert needs:
// absolute http/https URLs, Location-header redirect chasing, body read.

typedef struct { char *data; size_t len; } buf_t;

static int buf_append(buf_t *b, const void *p, size_t n) {
    char *np = realloc(b->data, b->len + n + 1);
    if (!np) return -1;
    b->data = np;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = 0;
    return 0;
}

// Parse "scheme://host[:port]/path" → components. Returns 0 on success.
static int url_split(const char *url, char *scheme, char *host, int *port,
                     char *path, size_t cap) {
    const char *p = strstr(url, "://");
    if (!p) return -1;
    size_t sl = (size_t)(p - url);
    if (sl >= cap) return -1;
    memcpy(scheme, url, sl);
    scheme[sl] = 0;

    int https = !strcmp(scheme, "https");
    if (!https && strcmp(scheme, "http") != 0) return -1;
    *port = https ? 443 : 80;

    const char *h = p + 3;
    const char *slash = strchr(h, '/');
    const char *hostend = slash ? slash : h + strlen(h);
    const char *colon = memchr(h, ':', (size_t)(hostend - h));

    size_t hl = (size_t)((colon ? colon : hostend) - h);
    if (hl >= cap) return -1;
    memcpy(host, h, hl);
    host[hl] = 0;

    if (colon) *port = atoi(colon + 1);

    if (slash) snprintf(path, cap, "%s", slash);
    else       snprintf(path, cap, "/");
    return 0;
}

// One GET. On success returns 0 with body in *body; if the response is a
// redirect, *location is set (caller follows). HTTP status in *status.
static int http_get_once(const char *url, int timeout_s, buf_t *body,
                          char *location, size_t loccap, int *status,
                          char *err, size_t errsz) {
    char scheme[16], host[256], path[1024];
    int port;
    if (url_split(url, scheme, host, &port, path, sizeof path) != 0) {
        snprintf(err, errsz, "unsupported URL: %s", url);
        return -1;
    }
    bool https = !strcmp(scheme, "https");

    int fd = dial(host, port, timeout_s, err, errsz);
    if (fd < 0) return -1;

    // Apply a coarse send/recv timeout so a half-open server can't wedge us.
    struct timeval tv = { timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (https) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { snprintf(err, errsz, "%s", ssl_errstr()); close(fd); return -1; }
        ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) {
            snprintf(err, errsz, "%s", ssl_errstr());
            SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
            return -1;
        }
    }

    char req[2048];
    int rn = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: tracep\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n",
                      path, host);

    bool wok;
    if (https) wok = SSL_write(ssl, req, rn) == rn;
    else       wok = write(fd, req, (size_t)rn) == rn;
    if (!wok) {
        snprintf(err, errsz, "write request failed");
        if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
        close(fd);
        return -1;
    }

    buf_t raw = { NULL, 0 };
    char tmp[8192];
    for (;;) {
        int n;
        if (https) n = SSL_read(ssl, tmp, sizeof tmp);
        else       n = (int)read(fd, tmp, sizeof tmp);
        if (n <= 0) break;
        if (buf_append(&raw, tmp, (size_t)n) != 0) break;
    }
    if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
    close(fd);

    if (!raw.data) { snprintf(err, errsz, "empty response"); return -1; }

    char *hdrend = strstr(raw.data, "\r\n\r\n");
    if (!hdrend) { free(raw.data); snprintf(err, errsz, "malformed HTTP response"); return -1; }

    *status = 0;
    if (sscanf(raw.data, "HTTP/%*d.%*d %d", status) != 1)
        sscanf(raw.data, "HTTP/%*d %d", status);

    location[0] = 0;
    // Case-insensitive scan for a Location: header in the header block.
    for (char *l = raw.data; l && l < hdrend; ) {
        char *nl = strstr(l, "\r\n");
        if (!nl || nl > hdrend) break;
        if (strncasecmp(l, "location:", 9) == 0) {
            char *v = l + 9;
            while (*v == ' ' || *v == '\t') v++;
            size_t vl = (size_t)(nl - v);
            if (vl >= loccap) vl = loccap - 1;
            memcpy(location, v, vl);
            location[vl] = 0;
        }
        l = nl + 2;
    }

    char *bodystart = hdrend + 4;
    size_t blen = raw.len - (size_t)(bodystart - raw.data);
    buf_append(body, bodystart, blen);
    free(raw.data);
    return 0;
}

// fetchDERCert: GET url (≤10 redirects), parse body as DER then PEM.
static X509 *fetch_der_cert(const char *url, int timeout_s, char *err, size_t errsz) {
    char cur[2048];
    snprintf(cur, sizeof cur, "%s", url);

    buf_t body = { NULL, 0 };
    for (int hop = 0; hop < 10; hop++) {
        free(body.data);
        body.data = NULL;
        body.len = 0;
        char loc[2048];
        int status = 0;
        if (http_get_once(cur, timeout_s, &body, loc, sizeof loc, &status, err, errsz) != 0)
            return NULL;
        if (status >= 300 && status < 400 && loc[0]) {
            // Resolve relative redirect targets against the current host.
            if (strstr(loc, "://")) {
                snprintf(cur, sizeof cur, "%s", loc);
            } else {
                char scheme[16], host[256], path[1024];
                int port;
                if (url_split(cur, scheme, host, &port, path, sizeof path) != 0) break;
                if (loc[0] == '/')
                    snprintf(cur, sizeof cur, "%s://%s:%d%s", scheme, host, port, loc);
                else
                    snprintf(cur, sizeof cur, "%s://%s:%d/%s", scheme, host, port, loc);
            }
            continue;
        }
        break;
    }

    if (!body.data || body.len == 0) {
        free(body.data);
        snprintf(err, errsz, "could not parse certificate from %s", url);
        return NULL;
    }

    // Try DER first.
    const unsigned char *p = (const unsigned char *)body.data;
    X509 *c = d2i_X509(NULL, &p, (long)body.len);
    if (c) { free(body.data); return c; }

    // Then PEM.
    BIO *bio = BIO_new_mem_buf(body.data, (int)body.len);
    if (bio) {
        c = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    free(body.data);
    if (!c) snprintf(err, errsz, "could not parse certificate from %s", url);
    return c;
}

// ── main ─────────────────────────────────────────────────────────────────────

int ca_main(int argc, char **argv) {
    (void)argv[0];                          // "tracep ca"

    char *pos[4];
    int posn = 0;

    for (int i = 1; i < argc; i++) {
        char *val = NULL;
        if (match_flag(argv, argc, &i, "port", false, &val)) {
            char *e; long v = strtol(val, &e, 10);
            if (e == val || *e) { fprintf(stderr, "invalid value %s for flag -port\n", val); exit(1); }
            fPort = (int)v;
            continue;
        }
        if (match_flag(argv, argc, &i, "fetch-root", true, &val)) { fFetchRoot = parse_bool(val); continue; }
        if (match_flag(argv, argc, &i, "insecure", true, &val))   { fInsecure  = parse_bool(val); continue; }
        if (match_flag(argv, argc, &i, "all", true, &val))        { fAll       = parse_bool(val); continue; }
        if (match_flag(argv, argc, &i, "version", true, &val))    { fShowVer   = parse_bool(val); continue; }
        if (match_flag(argv, argc, &i, "timeout", false, &val)) {
            char *e; long v = strtol(val, &e, 10);
            if (e == val || *e) { fprintf(stderr, "invalid value %s for flag -timeout\n", val); exit(1); }
            fTimeout = (int)v;
            continue;
        }
        if (match_flag(argv, argc, &i, "o", false, &val)) { fOutput = val; continue; }

        if (argv[i][0] == '-' && argv[i][1] != 0) {
            // Unknown flag: Go's flag.ExitOnError prints + exits non-zero.
            fprintf(stderr, "flag provided but not defined: %s\n", argv[i]);
            usage_err();
        }
        if (posn < 4) pos[posn++] = argv[i];
    }

    if (fShowVer) {
        // cafetch carries its own version (Go: var version = "v1.0.0",
        // patched via -ldflags at release), distinct from the tracep
        // binary version.
        printf("tls-ca-fetch %s\n", "v1.0.0");
        return 0;
    }

    if (posn < 1) {
        fprintf(stderr, "usage: tracep ca [flags] <hostname> [port]\n");
        print_defaults();
        exit(1);
    }

    const char *hostname = pos[0];

    if (posn >= 2) {
        char *e;
        long p = strtol(pos[1], &e, 10);
        if (e == pos[1] || *e || p < 1 || p > 65535) {
            fprintf(stderr, "invalid port: %s\n", pos[1]);
            exit(1);
        }
        fPort = (int)p;
    }

    printf("\xe2\x86\x92 Connecting to %s:%d \xe2\x80\xa6\n\n", hostname, fPort);

    char err[256] = { 0 };
    int fd = dial(hostname, fPort, fTimeout, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", err);
        exit(1);
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "error: %s\n", ssl_errstr());
        close(fd);
        exit(1);
    }
    if (!fInsecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, hostname);             // SNI
    if (!fInsecure) {
        X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set1_host(vp, hostname, 0);
    }
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        // Mirror Go's "error: %v" on dial/handshake failure.
        long vr = SSL_get_verify_result(ssl);
        if (!fInsecure && vr != X509_V_OK)
            fprintf(stderr, "error: tls: %s\n", X509_verify_cert_error_string(vr));
        else
            fprintf(stderr, "error: %s\n", ssl_errstr());
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        exit(1);
    }

    // Build the presented chain [leaf, then chain entries], skipping a
    // duplicate leaf — mirrors tls.ConnectionState.PeerCertificates.
    X509 *leaf = SSL_get_peer_certificate(ssl);          // bumps refcount
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);  // borrowed

    int chain_n = chain ? sk_X509_num(chain) : 0;
    int total = 0;
    X509 **certs = calloc((size_t)(chain_n + 1), sizeof *certs);

    int start = 0;
    if (leaf) {
        certs[total++] = leaf;
        // Skip the leaf if the chain repeats it as element 0.
        if (chain_n > 0 && X509_cmp(sk_X509_value(chain, 0), leaf) == 0)
            start = 1;
    }
    for (int i = start; i < chain_n; i++)
        certs[total++] = sk_X509_value(chain, i);

    if (total == 0) {
        fprintf(stderr, "error: server sent no certificates\n");
        if (leaf) X509_free(leaf);
        free(certs);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        exit(1);
    }

    printf("Chain received: %d certificate(s)\n", total);
    for (int i = 0; i < 70; i++) fputs("\xe2\x94\x80", stdout);
    fputc('\n', stdout);

    for (int i = 0; i < total; i++) {
        X509 *c = certs[i];
        char scn[512], icn[512], exp[32];
        name_cn(X509_get_subject_name(c), scn, sizeof scn);
        name_cn(X509_get_issuer_name(c), icn, sizeof icn);

        const char *role = cert_role(c, i);
        bool is_ca = (X509_check_ca(c) == 1);
        printf("  [%d] %-16s CN=%-40s IsCA=%s\n",
               i, role, short_cn(scn), is_ca ? "true" : "false");
        printf("       Issuer : %s\n", short_cn(icn));
        printf("       Expires: %s\n", not_after(c, exp, sizeof exp));
        char *aia = aia_ca_issuer(c);
        if (aia) {
            printf("       AIA    : %s\n", aia);
            free(aia);
        }
        printf("\n");
    }

    for (int i = 0; i < 70; i++) fputs("\xe2\x94\x80", stdout);
    fputc('\n', stdout);

    // Collect CA certs to save: -all OR idx>0 OR cert.IsCA.
    X509 **to_save = calloc((size_t)total + 1, sizeof *to_save);
    int save_n = 0;
    for (int i = 0; i < total; i++) {
        if (fAll || i > 0 || X509_check_ca(certs[i]) == 1)
            to_save[save_n++] = certs[i];
    }

    X509 *fetched_root = NULL;
    if (fFetchRoot) {
        X509 *top = certs[total - 1];
        char *aia = aia_ca_issuer(top);
        if (aia) {
            printf("\nFetching root CA via AIA: %s\n", aia);
            char ferr[256] = { 0 };
            fetched_root = fetch_der_cert(aia, fTimeout, ferr, sizeof ferr);
            if (!fetched_root) {
                fprintf(stderr, "warning: AIA fetch failed: %s\n", ferr);
            } else {
                char rcn[512], rexp[32];
                name_cn(X509_get_subject_name(fetched_root), rcn, sizeof rcn);
                printf("  Root: CN=%s  Expires: %s\n",
                       short_cn(rcn), not_after(fetched_root, rexp, sizeof rexp));
                to_save[save_n++] = fetched_root;
            }
            free(aia);
        } else {
            fprintf(stderr, "warning: no AIA URL found in topmost certificate\n");
        }
    }

    if (save_n == 0) {
        fprintf(stderr, "\nwarning: no CA certificates found in chain\n");
        char *leaf_aia = aia_ca_issuer(certs[0]);
        if (leaf_aia) {
            fprintf(stderr, "  Try -fetch-root. AIA URL: %s\n", leaf_aia);
            free(leaf_aia);
        }
        if (fetched_root) X509_free(fetched_root);
        if (leaf) X509_free(leaf);
        free(to_save);
        free(certs);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        exit(1);
    }

    // Output destination: -o, else "<hostname>-ca.pem"; "-" → stdout.
    char default_path[512];
    const char *out_path = fOutput;
    if (!out_path || !*out_path) {
        snprintf(default_path, sizeof default_path, "%s-ca.pem", hostname);
        out_path = default_path;
    }

    bool to_stdout = !strcmp(out_path, "-");
    FILE *w = stdout;
    if (!to_stdout) {
        w = fopen(out_path, "w");
        if (!w) {
            fprintf(stderr, "error: %s\n", strerror(errno));
            if (fetched_root) X509_free(fetched_root);
            if (leaf) X509_free(leaf);
            free(to_save);
            free(certs);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            exit(1);
        }
    }

    int pem_count = 0;
    for (int i = 0; i < save_n; i++) {
        if (PEM_write_X509(w, to_save[i]) != 1) {
            fprintf(stderr, "error writing PEM: %s\n", ssl_errstr());
            if (!to_stdout) fclose(w);
            if (fetched_root) X509_free(fetched_root);
            if (leaf) X509_free(leaf);
            free(to_save);
            free(certs);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            exit(1);
        }
        pem_count++;
    }

    if (!to_stdout) {
        fclose(w);
        printf("\n\xe2\x9c\x93 Saved %d CA certificate(s) \xe2\x86\x92 %s\n",
               pem_count, out_path);
        printf("  Verified: %d PEM block(s) readable in output file\n", pem_count);
    }

    if (fetched_root) X509_free(fetched_root);
    if (leaf) X509_free(leaf);
    free(to_save);
    free(certs);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
