//go:build !linux

package nettrace

import (
	"fmt"
	"os"
	"runtime"
)

// version is kept so release `-ldflags -X` resolves on every platform.
var version = "dev"

// Main is the non-Linux stub: connection tracing relies on conntrack
// netlink + /proc, which exist only on Linux.
func Main() {
	fmt.Fprintf(os.Stderr,
		"tracep net: network-connection tracing is only supported on Linux (this is %s).\n"+
			"Only `tracep ca` and `tracep dns` run on %s.\n",
		runtime.GOOS, runtime.GOOS)
	os.Exit(1)
}
