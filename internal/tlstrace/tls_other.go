//go:build !linux

package tlstrace

import (
	"fmt"
	"os"
	"runtime"
)

// version is kept so release `-ldflags -X` resolves on every platform.
var version = "dev"

// Main is the non-Linux stub: TLS capture relies on Linux ftrace uprobes
// on libssl, which have no macOS equivalent.
func Main() {
	fmt.Fprintf(os.Stderr,
		"tracep tls: TLS tracing is only supported on Linux (this is %s).\n"+
			"Only `tracep ca` and `tracep dns` run on %s.\n",
		runtime.GOOS, runtime.GOOS)
	os.Exit(1)
}
