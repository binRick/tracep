// common.h — shared helpers for the C port of tracep.
//
// Subcommand convention: each tracer exposes `int <name>_main(int argc,
// char **argv)` where argv[0] is "tracep <name>" (the dispatcher rewrites
// it, mirroring main.go). A tracer may also exit() directly on its error
// paths, exactly as the Go originals call os.Exit.
#ifndef TRACEP_COMMON_H
#define TRACEP_COMMON_H

#include <stdbool.h>
#include <stdio.h>

// Subcommand entry points (one per internal/* package).
int dns_main(int argc, char **argv);
int net_main(int argc, char **argv);
int tls_main(int argc, char **argv);
int exec_main(int argc, char **argv);
int ca_main(int argc, char **argv);

// Build version, patched by the Makefile via -DTRACEP_VERSION.
#ifndef TRACEP_VERSION
#define TRACEP_VERSION "dev"
#endif
extern const char *tracep_version;

// is_terminal reports whether the stream is an interactive char device —
// the portable check the Go code uses (ModeCharDevice), not a TCGETS ioctl.
bool is_terminal(FILE *f);

// want_color decides color: forced (-c) OR (stream is a tty AND $NO_COLOR
// unset). Mirrors the colorForce / NO_COLOR / isatty logic shared by every
// tracer.
bool want_color(bool force, FILE *f);

// clr wraps s in an ANSI SGR sequence "\033[<code>m...\033[0m" when `on`
// and s is non-empty, else returns s unchanged — the C twin of Go's clr().
// Results come from a rotating pool of buffers so several clr() calls can
// coexist as arguments to one printf (Go relied on string immutability;
// here we emulate it with N independent slots).
const char *clr(bool on, const char *code, const char *s);

// shquote returns a shell-safe rendering of s (POSIX single-quoting),
// matching exectrace.shQuote byte-for-byte. Result is in a rotating pool.
const char *shquote(const char *s);

#endif // TRACEP_COMMON_H
