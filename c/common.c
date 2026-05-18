#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *tracep_version = TRACEP_VERSION;

bool is_terminal(FILE *f) {
    if (!f) return false;
    int fd = fileno(f);
    struct stat st;
    if (fstat(fd, &st) != 0) return false;
    return S_ISCHR(st.st_mode);
}

bool want_color(bool force, FILE *f) {
    if (force) return true;
    return is_terminal(f) && getenv("NO_COLOR") == NULL;
}

// Rotating buffer pools. 16 slots is enough for the widest format line
// (net/exec compose ~7 colored fields per printf); 1 KB covers a colored
// field plus escapes.
#define POOL_N    16
#define POOL_SZ 1024

const char *clr(bool on, const char *code, const char *s) {
    if (!on || !s || !*s) return s ? s : "";
    static char pool[POOL_N][POOL_SZ];
    static int slot;
    char *b = pool[slot++ % POOL_N];
    snprintf(b, POOL_SZ, "\033[%sm%s\033[0m", code, s);
    return b;
}

// POSIX single-quote quoting, identical to exectrace.shQuote:
//  - empty             -> ''
//  - "safe" (no ctl/<=' ' and none of the metacharacters) -> as-is
//  - otherwise wrapped in '...', with ' -> '\'' and \n -> '$'\n''
const char *shquote(const char *s) {
    static char pool[POOL_N][POOL_SZ];
    static int slot;
    char *b = pool[slot++ % POOL_N];

    if (!s || !*s) { snprintf(b, POOL_SZ, "''"); return b; }

    bool safe = true;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p <= ' ' || strchr("`^#*[]=|\\?${}()'\"<>&;\x7f", *p)) { safe = false; break; }
    }
    if (safe) { snprintf(b, POOL_SZ, "%s", s); return b; }

    size_t w = 0;
    if (w < POOL_SZ - 1) b[w++] = '\'';
    for (const char *p = s; *p && w < POOL_SZ - 8; p++) {
        if (*p == '\'')      { memcpy(b + w, "'\\''", 4);     w += 4; }
        else if (*p == '\n') { memcpy(b + w, "'$'\\n''", 7);  w += 7; }
        else                 b[w++] = *p;
    }
    if (w < POOL_SZ - 1) b[w++] = '\'';
    b[w] = 0;
    return b;
}
