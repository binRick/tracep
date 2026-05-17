//go:build linux

package dnstrace

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// pidForUDPPort finds which PID owns a UDP socket on the given local port.
// Strategy:
//  1. Read /proc/net/udp (and /proc/net/udp6 for IPv6) to find the socket inode.
//  2. Walk /proc/<pid>/fd/ to find the PID that has a file descriptor pointing
//     to that inode (as "socket:[inode]").
//  3. Read /proc/<pid>/comm for the process name.
func pidForUDPPort(port uint16) (int, string) {
	inode, ok := inodeForPort(port, "/proc/net/udp")
	if !ok {
		inode, ok = inodeForPort(port, "/proc/net/udp6")
	}
	if !ok {
		return 0, "?"
	}

	target := fmt.Sprintf("socket:[%d]", inode)

	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "?"
	}

	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process may have exited
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid, commForPID(pid)
			}
		}
	}
	return 0, "?"
}

// inodeForPort reads a /proc/net/udp* file and returns the socket inode
// for the given local port. The file format is:
//
//	sl  local_address rem_address st tx_queue rx_queue tr:tm timeout inode
//
// local_address is XXXXXXXX:YYYY (big-endian hex IP : big-endian hex port).
func inodeForPort(port uint16, path string) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	portHex := fmt.Sprintf("%04X", port)
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// fields[1] = "XXXXXXXX:PPPP"
		colon := strings.LastIndexByte(fields[1], ':')
		if colon < 0 {
			continue
		}
		if strings.ToUpper(fields[1][colon+1:]) != portHex {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		return inode, true
	}
	return 0, false
}

// commForPID reads the process name from /proc/<pid>/comm.
func commForPID(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}
