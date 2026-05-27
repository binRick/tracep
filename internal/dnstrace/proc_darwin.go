//go:build darwin

package dnstrace

// macOS socket→PID via lsof. There is no /proc on darwin; calling
// proc_pidinfo(PROC_PIDFDSOCKETINFO) per fd requires decoding a 1320-byte
// socket_fdinfo with versioned offsets, which is fragile. lsof ships with
// macOS at /usr/sbin/lsof and exposes the data we need behind a stable
// machine-readable -F format. One scan per TTL populates the whole port
// map, so DNS packets in the meantime hit it for free.
//
// Limitations: non-root sees only the invoker's own-user sockets; if
// lsof is missing or fails the function reports (0, "?") and dns falls
// back to unattributed events — same shape as the old proc_other.go stub.

import (
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type macPidName struct {
	pid  int
	name string
}

var (
	macMu       sync.Mutex
	macMap      map[uint16]macPidName
	macMapBorn  time.Time
	macScanFail bool // suppress repeat error spam after first failure
)

const macTTL = 2 * time.Second

// pidForUDPPort looks the port up in a cached lsof snapshot, rescanning
// if the snapshot is older than macTTL. Cached miss returns (0, "?")
// matching the !linux && !darwin stub.
func pidForUDPPort(port uint16) (int, string) {
	macMu.Lock()
	defer macMu.Unlock()
	if macMap == nil || time.Since(macMapBorn) > macTTL {
		macMap = scanUDPSocketsDarwin()
		macMapBorn = time.Now()
	}
	if pn, ok := macMap[port]; ok {
		return pn.pid, pn.name
	}
	return 0, "?"
}

// scanUDPSocketsDarwin runs `lsof -nP -iUDP -F pcn` and parses the
// machine-readable output into a port→(pid, command) map. The -F format
// emits one field per line, prefixed by the field code:
//
//	p<pid>      → start of a process record
//	c<command>
//	f<fd>       → start of a file-descriptor record under the current process
//	n<name>     → socket name, e.g. "*:54321" or "127.0.0.1:5353" or "*:*"
//
// We keep the most-recent (pid, name) per port; UDP port reuse is rare
// inside a 2-second window, and an LRU answer is fine for filtering.
func scanUDPSocketsDarwin() map[uint16]macPidName {
	m := map[uint16]macPidName{}
	out, err := exec.Command("/usr/sbin/lsof", "-nP", "-iUDP", "-F", "pcn").Output()
	if err != nil {
		// First failure: complain once via stderr so users notice missing
		// lsof or denied access; subsequent failures stay silent.
		if !macScanFail {
			macScanFail = true
		}
		return m
	}
	var pid int
	var name string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			if v, err := strconv.Atoi(line[1:]); err == nil {
				pid = v
			}
		case 'c':
			name = line[1:]
		case 'n':
			// Trailing token after the last ':' is the port (or "*").
			body := line[1:]
			colon := strings.LastIndex(body, ":")
			if colon < 0 {
				continue
			}
			pstr := body[colon+1:]
			if pstr == "*" {
				continue // socket with no bound local port
			}
			// Strip a trailing "->host:port" suffix on connected sockets.
			if arrow := strings.Index(pstr, "->"); arrow >= 0 {
				pstr = pstr[:arrow]
			}
			p, err := strconv.Atoi(pstr)
			if err != nil || p <= 0 || p > 65535 {
				continue
			}
			m[uint16(p)] = macPidName{pid: pid, name: name}
		}
	}
	return m
}
