// tracep — trace a process's network, TLS, DNS, and exec activity.
//
// One self-contained Go binary unifying the proc-trace-{net,tls,dns,exec}
// tracers plus the TLS CA fetcher. Each subcommand keeps its original
// flags and behaviour; this file only dispatches to the right one.
package main

import (
	"fmt"
	"os"

	"github.com/binRick/tracep/internal/cafetch"
	"github.com/binRick/tracep/internal/dnstrace"
	"github.com/binRick/tracep/internal/exectrace"
	"github.com/binRick/tracep/internal/nettrace"
	"github.com/binRick/tracep/internal/tlstrace"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// It must stay a var (not const) for the linker to patch it.
var version = "dev"

var subcommands = []struct {
	name, desc string
	run        func()
}{
	{"net", "trace per-process network connections", nettrace.Main},
	{"tls", "trace per-process TLS handshakes", tlstrace.Main},
	{"dns", "trace per-process DNS queries", dnstrace.Main},
	{"exec", "trace per-process exec syscalls", exectrace.Main},
	{"ca", "fetch a host's TLS CA chain", cafetch.Main},
}

func usage() {
	fmt.Fprintf(os.Stderr, "tracep %s — trace a process's net, TLS, DNS & exec activity\n\n", version)
	fmt.Fprintf(os.Stderr, "usage: tracep <command> [flags]\n\ncommands:\n")
	for _, s := range subcommands {
		fmt.Fprintf(os.Stderr, "  %-6s %s\n", s.name, s.desc)
	}
	fmt.Fprintf(os.Stderr, "\nrun 'tracep <command> -h' for command-specific flags\n")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	if sub == "-h" || sub == "--help" || sub == "help" {
		usage()
		return
	}
	if sub == "-v" || sub == "--version" || sub == "version" {
		fmt.Println("tracep", version)
		return
	}

	// Rewrite os.Args so each subcommand's own argument parsing
	// (manual os.Args[1:] slicing in net/tls/exec, the global flag
	// package in dns/ca) sees exactly its flags — argv[0] becomes
	// "tracep <sub>" so usage strings stay sensible.
	os.Args = append([]string{os.Args[0] + " " + sub}, os.Args[2:]...)

	for _, s := range subcommands {
		if s.name == sub {
			s.run()
			return
		}
	}
	fmt.Fprintf(os.Stderr, "tracep: unknown command %q\n\n", sub)
	usage()
	os.Exit(2)
}
