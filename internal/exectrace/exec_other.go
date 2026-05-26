//go:build !linux && !darwin

package exectrace

import (
	"fmt"
	"os"
	"runtime"
)

// version is kept so release `-ldflags -X` resolves on every platform.
var version = "dev"

// Main is the fallback stub for OSes with no exec tracer. Linux uses the
// netlink proc connector (exec_linux.go); darwin uses proc_listallpids
// polling (exec_darwin.go); everything else exits with a clear message.
func Main() {
	fmt.Fprintf(os.Stderr,
		"tracep exec: exec() tracing is only supported on Linux and macOS (this is %s).\n"+
			"Only `tracep ca` and `tracep dns` run on %s.\n",
		runtime.GOOS, runtime.GOOS)
	os.Exit(1)
}
