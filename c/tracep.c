// tracep — trace a process's network, TLS, DNS, and exec activity.
//
// C port of the Go binary. One self-contained executable unifying the
// proc-trace-{net,tls,dns,exec} tracers plus the TLS CA fetcher. This file
// only dispatches to the right subcommand (mirrors main.go).
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct {
    const char *name, *desc;
    int (*run)(int, char **);
} subcommands[] = {
    {"net",  "trace per-process network connections", net_main},
    {"tls",  "trace per-process TLS handshakes",       tls_main},
    {"dns",  "trace per-process DNS queries",          dns_main},
    {"exec", "trace per-process exec syscalls",        exec_main},
    {"ca",   "fetch a host's TLS CA chain",            ca_main},
};
#define NSUB ((int)(sizeof subcommands / sizeof subcommands[0]))

static void usage(void) {
    fprintf(stderr, "tracep %s — trace a process's net, TLS, DNS & exec activity\n\n",
            tracep_version);
    fprintf(stderr, "usage: tracep <command> [flags]\n\ncommands:\n");
    for (int i = 0; i < NSUB; i++)
        fprintf(stderr, "  %-6s %s\n", subcommands[i].name, subcommands[i].desc);
    fprintf(stderr, "\nrun 'tracep <command> -h' for command-specific flags\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }

    const char *sub = argv[1];
    if (!strcmp(sub, "-h") || !strcmp(sub, "--help") || !strcmp(sub, "help")) {
        usage();
        return 0;
    }
    if (!strcmp(sub, "-v") || !strcmp(sub, "--version") || !strcmp(sub, "version")) {
        printf("tracep %s\n", tracep_version);
        return 0;
    }

    // Rewrite argv so each subcommand sees exactly its own flags, with
    // argv[0] == "tracep <sub>" so usage strings stay sensible (mirrors
    // the os.Args rewrite in main.go).
    for (int i = 0; i < NSUB; i++) {
        if (strcmp(subcommands[i].name, sub) != 0) continue;
        char prog[64];
        snprintf(prog, sizeof prog, "tracep %s", sub);
        int sub_argc = argc - 1;
        char **sub_argv = argv + 1;
        sub_argv[0] = prog;
        return subcommands[i].run(sub_argc, sub_argv);
    }

    fprintf(stderr, "tracep: unknown command \"%s\"\n\n", sub);
    usage();
    return 2;
}
