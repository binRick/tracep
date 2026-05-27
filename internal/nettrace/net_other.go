//go:build !linux && !darwin

package nettrace

import (
	"fmt"
	"os"
	"runtime"
)

// version is kept so release `-ldflags -X` resolves on every platform.
var version = "dev"

// Main is the fallback stub. Linux uses conntrack netlink + /proc
// (net.go); darwin polls lsof (net_darwin.go); other OSes get this
// clear refusal.
func Main() {
	fmt.Fprintf(os.Stderr,
		"tracep net: network-connection tracing is only supported on Linux and macOS (this is %s).\n"+
			"Only `tracep ca` and `tracep dns` run on %s.\n",
		runtime.GOOS, runtime.GOOS)
	os.Exit(1)
}
