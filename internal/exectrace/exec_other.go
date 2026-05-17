//go:build !linux

package exectrace

import (
	"fmt"
	"os"
	"runtime"
)

// version is kept so release `-ldflags -X` resolves on every platform.
var version = "dev"

// Main is the non-Linux stub: exec() tracing relies on the Linux proc
// connector (netlink); macOS would require the EndpointSecurity framework
// with an Apple entitlement.
func Main() {
	fmt.Fprintf(os.Stderr,
		"tracep exec: exec() tracing is only supported on Linux (this is %s).\n"+
			"Only `tracep ca` and `tracep dns` run on %s.\n",
		runtime.GOOS, runtime.GOOS)
	os.Exit(1)
}
