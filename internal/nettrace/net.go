//go:build linux

// proc-trace-net — trace network connections system-wide via Linux conntrack netlink
//
// Requires CONFIG_NF_CONNTRACK=y (nf_conntrack module, standard on any Linux running Docker)
// Requires root or CAP_NET_ADMIN
//
// Usage: proc-trace-net [-crtUuQo46O] [-o FILE] [-p PID[,PID,...] | CMD...]
package nettrace

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─── Netfilter / conntrack constants ──────────────────────────────────────────

const (
	netlinkNetfilter = 12 // NETLINK_NETFILTER

	// Conntrack multicast groups (bitmask for nl_groups)
	nfConntrackNew     = uint32(1) // bit 0 — new connections
	nfConntrackUpdate  = uint32(2) // bit 1 — TCP state changes
	nfConntrackDestroy = uint32(4) // bit 2 — closed connections

	// Netfilter subsystem
	nfnlSubsysCtnetlink = 1

	// Conntrack message types: (subsys<<8 | msg_type)
	msgCtNew    = (nfnlSubsysCtnetlink << 8) | 0 // 256
	msgCtDelete = (nfnlSubsysCtnetlink << 8) | 2 // 258

	nfgenMsgSize = 4 // sizeof(struct nfgenmsg)

	// NLA flags (top 2 bits of nla_type)
	nlaFNested       = uint16(0x8000)
	nlaFNetByteorder = uint16(0x4000)

	// Top-level CTA attributes
	ctaTupleOrig = uint16(1)
	ctaProtoinfo = uint16(4)

	// CTA_TUPLE sub-attrs
	ctaTupleIP    = uint16(1)
	ctaTupleProto = uint16(2)

	// CTA_TUPLE_IP sub-attrs
	ctaIPv4Src = uint16(1)
	ctaIPv4Dst = uint16(2)
	ctaIPv6Src = uint16(3)
	ctaIPv6Dst = uint16(4)

	// CTA_TUPLE_PROTO sub-attrs
	ctaProtoNum     = uint16(1)
	ctaProtoSrcPort = uint16(2)
	ctaProtoDstPort = uint16(3)

	// CTA_PROTOINFO sub-attrs
	ctaProtoinfoTCP = uint16(1)

	// CTA_PROTOINFO_TCP sub-attrs
	ctaProtoinfoTCPState = uint16(1)

	// nlmsghdr flags
	nlmFCreate = uint16(0x400)
)

// conntrack TCP state names (enum tcp_conntrack in kernel)
var tcpStateNames = [12]string{
	"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED",
	"FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT",
	"CLOSE", "LISTEN", "MAX", "IGNORE",
}

func tcpStateName(s uint8) string {
	if int(s) < len(tcpStateNames) {
		return tcpStateNames[s]
	}
	return fmt.Sprintf("STATE%d", s)
}

// ─── Connection tuple ─────────────────────────────────────────────────────────

type connTuple struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

func (t *connTuple) key() string {
	return fmt.Sprintf("%s:%d|%s:%d|%d",
		t.SrcIP.String(), t.SrcPort, t.DstIP.String(), t.DstPort, t.Proto)
}

func (t *connTuple) protoStr() string {
	switch t.Proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("IP%d", t.Proto)
	}
}

// ─── Connection direction ─────────────────────────────────────────────────────

type direction uint8

const (
	dirUnknown  direction = 0
	dirOutbound direction = 1
	dirInbound  direction = 2
)

func (d direction) arrow() string {
	switch d {
	case dirOutbound:
		return "→"
	case dirInbound:
		return "←"
	default:
		return "↔"
	}
}

// ─── Active connection tracking (for -t close timing) ────────────────────────

type connEntry struct {
	tuple    connTuple
	pid      int32
	comm     string
	dir      direction
	startAt  time.Time
	tcpState uint8
}

var (
	connMu sync.Mutex
	connDB = make(map[string]*connEntry)
)

// ─── Local IP cache (for direction fallback when socket is in container netns) ─

var (
	localIPsMu   sync.Once
	localIPsSet  = make(map[string]bool)
)

func initLocalIPs() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					localIPsSet[v4.String()] = true
				} else {
					localIPsSet[ip.String()] = true
				}
			}
		}
	}
}

func isLocalIP(ip net.IP) bool {
	localIPsMu.Do(initLocalIPs)
	if v4 := ip.To4(); v4 != nil {
		return localIPsSet[v4.String()]
	}
	return localIPsSet[ip.String()]
}

// ─── Async reverse DNS cache ─────────────────────────────────────────────────

var (
	dnsMu      sync.Mutex
	dnsCache   = make(map[string]string)
	dnsLaunced = make(map[string]bool)
)

// asyncReverseLookup returns a cached hostname, launching a background lookup
// on first call. Empty string if not yet resolved or no PTR record.
func asyncReverseLookup(ip string) string {
	dnsMu.Lock()
	name := dnsCache[ip]
	launched := dnsLaunced[ip]
	dnsMu.Unlock()

	if !launched {
		dnsMu.Lock()
		dnsLaunced[ip] = true
		dnsMu.Unlock()
		go func() {
			names, _ := net.LookupAddr(ip)
			var resolved string
			if len(names) > 0 {
				resolved = strings.TrimRight(names[0], ".")
			}
			dnsMu.Lock()
			dnsCache[ip] = resolved
			dnsMu.Unlock()
		}()
	}
	return name
}

// ─── Global options ───────────────────────────────────────────────────────────

var version = "dev"

var (
	watchPIDs   []int32
	showClose    bool // -t: show DESTROY events with elapsed time
	showUpdate   bool // -U: show TCP state update events
	showUser     bool // -u: print owning user
	showReverse  bool // -r: reverse DNS for remote IPs
	ipv4Only     bool // -4
	ipv6Only     bool // -6
	outboundOnly bool // -O: outbound connections only
	showErrors   = true
	colorMode   bool
	colorForce  bool
	out         io.Writer = os.Stdout
)

// ─── Color helpers ────────────────────────────────────────────────────────────

func clr(code, s string) string {
	if !colorMode || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ─── main ─────────────────────────────────────────────────────────────────────

func Main() {
	args := os.Args[1:]
	var cmdArgs []string
	var outFile string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			cmdArgs = args[i:]
			break
		}
		for _, ch := range a[1:] {
			switch ch {
			case 'c':
				colorForce = true
			case 't':
				showClose = true
			case 'U':
				showUpdate = true
			case 'u':
				showUser = true
			case 'r':
				showReverse = true
			case '4':
				ipv4Only = true
			case '6':
				ipv6Only = true
			case 'O':
				outboundOnly = true
			case 'Q':
				showErrors = false
			case 'p':
				if i+1 >= len(args) {
					fatal("flag -p requires an argument")
				}
				i++
				for _, s := range strings.Split(args[i], ",") {
					s = strings.TrimSpace(s)
					if s == "" {
						continue
					}
					pid, err := strconv.Atoi(s)
					if err != nil || pid <= 0 {
						fatalf("-p: invalid PID: %s", s)
					}
					if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
						fatalf("-p %d: no such process", pid)
					}
					watchPIDs = append(watchPIDs, int32(pid))
				}
			case 'o':
				if i+1 >= len(args) {
					fatal("flag -o requires an argument")
				}
				i++
				outFile = args[i]
			case 'h':
				usage()
			default:
				fatalf("unknown flag -%c", ch)
			}
		}
	}

	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fatalf("open %s: %v", outFile, err)
		}
		defer f.Close()
		out = f
	}

	if colorForce {
		colorMode = true
	} else if os.Getenv("NO_COLOR") == "" {
		if f, ok := out.(*os.File); ok {
			colorMode = isTerminal(f)
		}
	}

	groups := nfConntrackNew | nfConntrackDestroy
	if showUpdate {
		groups |= nfConntrackUpdate
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkNetfilter)
	if err != nil {
		fatalf("socket: %v\nhint: requires CAP_NET_ADMIN (run as root)", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: groups,
		Pid:    uint32(os.Getpid()),
	}
	if err := syscall.Bind(fd, sa); err != nil {
		fatalf("bind: %v\nhint: is nf_conntrack loaded? try: modprobe nf_conntrack", err)
	}

	// CMD mode: launch command and trace only its network connections
	if len(cmdArgs) > 0 {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fatalf("exec %s: %v", cmdArgs[0], err)
		}
		watchPIDs = append(watchPIDs, int32(cmd.Process.Pid))
		go func() {
			_ = cmd.Wait()
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
	}

	buf := make([]byte, 1<<20) // 1 MB — enough for large bursts
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if showErrors {
				fmt.Fprintf(os.Stderr, "proc-trace-net: recvfrom: %v\n", err)
			}
			continue
		}
		processNlMsgs(buf[:n])
	}
}

// ─── Netlink message dispatch ─────────────────────────────────────────────────

func processNlMsgs(data []byte) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return
	}
	for _, msg := range msgs {
		t := int(msg.Header.Type)
		if t != msgCtNew && t != msgCtDelete {
			continue
		}
		if len(msg.Data) < nfgenMsgSize {
			continue
		}
		payload := msg.Data[nfgenMsgSize:]

		orig := parseTuple(payload, ctaTupleOrig)
		if orig == nil {
			continue
		}

		// IP version filter
		is4 := orig.SrcIP.To4() != nil
		if ipv4Only && !is4 {
			continue
		}
		if ipv6Only && is4 {
			continue
		}

		// Only TCP and UDP
		if orig.Proto != 6 && orig.Proto != 17 {
			continue
		}

		key := orig.key()
		isNew := t == msgCtNew
		isCreate := (msg.Header.Flags & nlmFCreate) != 0

		switch {
		case isNew && isCreate:
			handleNew(key, orig, payload)
		case isNew && !isCreate && showUpdate:
			handleUpdate(key, orig, payload)
		case !isNew && showClose:
			handleDestroy(key, orig)
		case !isNew:
			// Clean up DB even when not displaying close events
			connMu.Lock()
			delete(connDB, key)
			connMu.Unlock()
		}
	}
}

// ─── Event handlers ───────────────────────────────────────────────────────────

func handleNew(key string, orig *connTuple, payload []byte) {
	pid, comm, dir := findPIDAndDir(orig)

	if len(watchPIDs) > 0 && !isWatched(pid) {
		return
	}
	if outboundOnly && dir == dirInbound {
		return
	}

	var tcpState uint8
	if orig.Proto == 6 {
		tcpState = parseTCPState(payload)
	}

	connMu.Lock()
	connDB[key] = &connEntry{
		tuple:    *orig,
		pid:      pid,
		comm:     comm,
		dir:      dir,
		startAt:  time.Now(),
		tcpState: tcpState,
	}
	connMu.Unlock()

	printEvent(orig, pid, comm, dir, "", "")
}

func handleUpdate(key string, orig *connTuple, payload []byte) {
	connMu.Lock()
	ent := connDB[key]
	connMu.Unlock()

	var pid int32
	var comm string
	var dir direction

	if ent != nil {
		pid = ent.pid
		comm = ent.comm
		dir = ent.dir
	}

	if len(watchPIDs) > 0 && !isWatched(pid) {
		return
	}
	if outboundOnly && dir == dirInbound {
		return
	}

	var stateName string
	if orig.Proto == 6 {
		s := parseTCPState(payload)
		stateName = tcpStateName(s)
		if ent != nil {
			connMu.Lock()
			ent.tcpState = s
			connMu.Unlock()
		}
	}

	printEvent(orig, pid, comm, dir, "UPDATE", stateName)
}

func handleDestroy(key string, orig *connTuple) {
	connMu.Lock()
	ent := connDB[key]
	delete(connDB, key)
	connMu.Unlock()

	if ent == nil {
		// Connection pre-dates our start; nothing to show
		return
	}
	if len(watchPIDs) > 0 && !isWatched(ent.pid) {
		return
	}

	elapsed := fmt.Sprintf("%.3fs", time.Since(ent.startAt).Seconds())
	printEvent(orig, ent.pid, ent.comm, ent.dir, "CLOSED", elapsed)
}

// ─── Output ───────────────────────────────────────────────────────────────────

func printEvent(orig *connTuple, pid int32, comm string, dir direction, event, extra string) {
	var sb strings.Builder

	// PID
	if pid > 0 {
		sb.WriteString(clr("33", fmt.Sprintf("%5d", pid)))
	} else {
		sb.WriteString(clr("2", "    ?"))
	}
	sb.WriteByte(' ')

	// Comm (12-wide)
	if comm != "" {
		sb.WriteString(clr("96", fmt.Sprintf("%-12s", comm)))
	} else {
		sb.WriteString(clr("2", fmt.Sprintf("%-12s", "?")))
	}

	// User
	if showUser && pid > 0 {
		uname := procUser(pid)
		if uname == "root" {
			sb.WriteString(clr("91", " <"+uname+">"))
		} else {
			sb.WriteString(clr("92", " <"+uname+">"))
		}
	}
	sb.WriteByte(' ')

	// Protocol (4-wide)
	sb.WriteString(clr("2", fmt.Sprintf("%-4s", orig.protoStr())))
	sb.WriteByte(' ')

	// Source address (24-wide)
	srcStr := fmt.Sprintf("%s:%d", orig.SrcIP.String(), orig.SrcPort)
	sb.WriteString(clr("32", fmt.Sprintf("%-24s", srcStr)))
	sb.WriteByte(' ')

	// Direction indicator / event marker
	switch event {
	case "CLOSED":
		sb.WriteString(clr("31", "×"))
	case "UPDATE":
		sb.WriteString(clr("35", "⇒"))
	default:
		sb.WriteString(clr("36", dir.arrow()))
	}
	sb.WriteByte(' ')

	// Destination address (24-wide)
	dstStr := fmt.Sprintf("%s:%d", orig.DstIP.String(), orig.DstPort)
	sb.WriteString(clr("33", fmt.Sprintf("%-24s", dstStr)))

	// Reverse DNS (async; empty on first occurrence, fills in on subsequent events)
	if showReverse {
		lookupIP := orig.DstIP.String()
		if dir == dirInbound {
			lookupIP = orig.SrcIP.String()
		}
		if host := asyncReverseLookup(lookupIP); host != "" {
			sb.WriteString(clr("2", " ["+host+"]"))
		}
	}

	// Extra: state name (UPDATE) or elapsed time (CLOSED)
	if extra != "" {
		sb.WriteByte(' ')
		sb.WriteString(clr("36", extra))
	}

	fmt.Fprintln(out, sb.String())
}

// ─── NLA (netlink attribute) parsing ─────────────────────────────────────────

// parseNLAttrs parses a flat list of netlink attributes from data.
// Strips NLA_F_NESTED and NLA_F_NET_BYTEORDER from attribute types.
func parseNLAttrs(data []byte) map[uint16][]byte {
	attrs := make(map[uint16][]byte)
	for len(data) >= 4 {
		nlaLen := binary.LittleEndian.Uint16(data[0:2])
		nlaType := binary.LittleEndian.Uint16(data[2:4]) &^ nlaFNested &^ nlaFNetByteorder
		if nlaLen < 4 {
			break
		}
		end := int(nlaLen)
		if end > len(data) {
			break
		}
		attrs[nlaType] = data[4:end]
		aligned := (end + 3) &^ 3
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
	return attrs
}

// parseTuple extracts src/dst IP, port, and protocol from a conntrack payload.
// tupleAttr selects CTA_TUPLE_ORIG (1) or CTA_TUPLE_REPLY (2).
func parseTuple(payload []byte, tupleAttr uint16) *connTuple {
	top := parseNLAttrs(payload)
	tupleData, ok := top[tupleAttr]
	if !ok {
		return nil
	}
	ta := parseNLAttrs(tupleData)

	var t connTuple

	if ipData, ok := ta[ctaTupleIP]; ok {
		ia := parseNLAttrs(ipData)
		if v, ok := ia[ctaIPv4Src]; ok && len(v) == 4 {
			ip := make(net.IP, 4)
			copy(ip, v)
			t.SrcIP = ip
		}
		if v, ok := ia[ctaIPv4Dst]; ok && len(v) == 4 {
			ip := make(net.IP, 4)
			copy(ip, v)
			t.DstIP = ip
		}
		if v, ok := ia[ctaIPv6Src]; ok && len(v) == 16 {
			ip := make(net.IP, 16)
			copy(ip, v)
			t.SrcIP = ip
		}
		if v, ok := ia[ctaIPv6Dst]; ok && len(v) == 16 {
			ip := make(net.IP, 16)
			copy(ip, v)
			t.DstIP = ip
		}
	}

	if protoData, ok := ta[ctaTupleProto]; ok {
		pa := parseNLAttrs(protoData)
		if v, ok := pa[ctaProtoNum]; ok && len(v) >= 1 {
			t.Proto = v[0]
		}
		if v, ok := pa[ctaProtoSrcPort]; ok && len(v) >= 2 {
			t.SrcPort = binary.BigEndian.Uint16(v)
		}
		if v, ok := pa[ctaProtoDstPort]; ok && len(v) >= 2 {
			t.DstPort = binary.BigEndian.Uint16(v)
		}
	}

	if t.SrcIP == nil || t.DstIP == nil {
		return nil
	}
	return &t
}

func parseTCPState(payload []byte) uint8 {
	top := parseNLAttrs(payload)
	piData, ok := top[ctaProtoinfo]
	if !ok {
		return 0
	}
	piAttrs := parseNLAttrs(piData)
	tcpData, ok := piAttrs[ctaProtoinfoTCP]
	if !ok {
		return 0
	}
	tcpAttrs := parseNLAttrs(tcpData)
	stateData, ok := tcpAttrs[ctaProtoinfoTCPState]
	if !ok || len(stateData) < 1 {
		return 0
	}
	return stateData[0]
}

// ─── PID lookup via /proc/net/tcp + inode scan ────────────────────────────────

func findPIDAndDir(orig *connTuple) (int32, string, direction) {
	inode, dir := findInodeWithDir(orig)
	if inode == 0 {
		// Socket not in host netns (e.g. Docker container). Fall back to
		// IP-based heuristic: if DstIP is local the connection is inbound.
		if isLocalIP(orig.DstIP) {
			dir = dirInbound
		} else if isLocalIP(orig.SrcIP) {
			dir = dirOutbound
		}
		return 0, "", dir
	}
	pid, comm := inodeToPID(inode)
	return pid, comm, dir
}

type procEntry struct {
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16
	inode      uint64
}

func findInodeWithDir(orig *connTuple) (uint64, direction) {
	var files []string
	switch orig.Proto {
	case 6:
		files = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case 17:
		files = []string{"/proc/net/udp", "/proc/net/udp6"}
	default:
		return 0, dirUnknown
	}

	for _, f := range files {
		entries := readProcNetFile(f)
		for _, e := range entries {
			if e.inode == 0 {
				continue
			}
			// Outbound: local side owns the source port
			if ipsEq(e.localIP, orig.SrcIP) && e.localPort == orig.SrcPort &&
				ipsEq(e.remoteIP, orig.DstIP) && e.remotePort == orig.DstPort {
				return e.inode, dirOutbound
			}
			// Inbound: local side owns the destination port
			if ipsEq(e.localIP, orig.DstIP) && e.localPort == orig.DstPort &&
				ipsEq(e.remoteIP, orig.SrcIP) && e.remotePort == orig.SrcPort {
				return e.inode, dirInbound
			}
		}
		// UDP fallback: unconnected sockets only have a local addr
		if orig.Proto == 17 {
			for _, e := range entries {
				if e.inode == 0 {
					continue
				}
				if ipsEq(e.localIP, orig.SrcIP) && e.localPort == orig.SrcPort {
					return e.inode, dirOutbound
				}
			}
		}
	}
	return 0, dirUnknown
}

func readProcNetFile(filename string) []procEntry {
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []procEntry
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // skip header line
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		lp := strings.SplitN(fields[1], ":", 2)
		rp := strings.SplitN(fields[2], ":", 2)
		if len(lp) != 2 || len(rp) != 2 {
			continue
		}
		var localIP, remoteIP net.IP
		switch len(lp[0]) {
		case 8: // IPv4: 8 hex chars
			localIP = parseHexIPv4(lp[0])
			remoteIP = parseHexIPv4(rp[0])
		case 32: // IPv6: 32 hex chars
			localIP = parseHexIPv6(lp[0])
			remoteIP = parseHexIPv6(rp[0])
		default:
			continue
		}
		if localIP == nil || remoteIP == nil {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		entries = append(entries, procEntry{
			localIP:    localIP,
			localPort:  parseHexPort(lp[1]),
			remoteIP:   remoteIP,
			remotePort: parseHexPort(rp[1]),
			inode:      inode,
		})
	}
	return entries
}

// parseHexIPv4 converts "0100007F" → net.IP{127,0,0,1}.
// The kernel prints IPv4 as a native-endian (little-endian on x86) uint32,
// so we extract bytes from LSB to MSB to recover the network-order address.
func parseHexIPv4(s string) net.IP {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil
	}
	return net.IP{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// parseHexIPv6 converts a 32-char hex string (4 × 8-char LE words) to net.IP.
// The kernel prints each 32-bit word of struct in6_addr as a native-endian %08X.
func parseHexIPv6(s string) net.IP {
	if len(s) != 32 {
		return nil
	}
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(s[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return nil
		}
		ip[i*4+0] = byte(v)
		ip[i*4+1] = byte(v >> 8)
		ip[i*4+2] = byte(v >> 16)
		ip[i*4+3] = byte(v >> 24)
	}
	return ip
}

func parseHexPort(s string) uint16 {
	v, _ := strconv.ParseUint(s, 16, 16)
	return uint16(v)
}

// ipsEq compares two IPs, normalizing IPv4-mapped IPv6 → IPv4 first.
func ipsEq(a, b net.IP) bool {
	if v := a.To4(); v != nil {
		a = v
	}
	if v := b.To4(); v != nil {
		b = v
	}
	return bytes.Equal(a, b)
}

func inodeToPID(inode uint64) (int32, string) {
	target := fmt.Sprintf("socket:[%d]", inode)
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, ""
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				return int32(pid), strings.TrimRight(string(comm), "\n")
			}
		}
	}
	return 0, ""
}

// ─── PID ancestry (for -p and CMD mode) ─────────────────────────────────────

// isWatched returns true if pid is one of the watched PIDs or a descendant.
func isWatched(pid int32) bool {
	if pid <= 0 {
		return false
	}
	for _, w := range watchPIDs {
		if pid == w {
			return true
		}
	}
	return isDescendant(pid)
}

func isDescendant(pid int32) bool {
	seen := make(map[int32]bool)
	for p := pid; p > 1; {
		if seen[p] {
			return false
		}
		seen[p] = true
		ppid := statPPID(p)
		if ppid <= 0 {
			return false
		}
		for _, w := range watchPIDs {
			if ppid == w {
				return true
			}
		}
		p = ppid
	}
	return false
}

func statPPID(pid int32) int32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return -1
	}
	idx := bytes.LastIndexByte(data, ')')
	if idx < 0 {
		return -1
	}
	rest := strings.TrimLeft(string(data[idx+1:]), " ")
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return -1
	}
	ppid, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return -1
	}
	return int32(ppid)
}

// ─── Process info ─────────────────────────────────────────────────────────────

func procUser(pid int32) string {
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return "?"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "?"
	}
	u, err := user.LookupId(strconv.Itoa(int(stat.Uid)))
	if err != nil {
		return strconv.Itoa(int(stat.Uid))
	}
	return u.Username
}

// ─── Error helpers ────────────────────────────────────────────────────────────

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "proc-trace-net: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "proc-trace-net: "+msg)
	os.Exit(1)
}

// ─── Usage ────────────────────────────────────────────────────────────────────

func usage() {
	const (
		bold    = "\033[1m"
		dim     = "\033[2m"
		reset   = "\033[0m"
		cyan    = "\033[36m"
		yellow  = "\033[33m"
		green   = "\033[32m"
		magenta = "\033[35m"
	)
	e := os.Stderr
	fmt.Fprintf(e, "\n  %s🌐 proc-trace-net%s %s%s%s — system-wide network connection tracer for Linux\n\n", bold+cyan, reset, dim, version, reset)
	fmt.Fprintf(e, "  %sRequires:%s root or CAP_NET_ADMIN, nf_conntrack kernel module\n\n", bold, reset)
	fmt.Fprintf(e, "  %sUsage:%s\n", bold, reset)
	fmt.Fprintf(e, "    proc-trace-net %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n", dim, reset, yellow, reset)
	fmt.Fprintf(e, "  %sFlags:%s\n", bold, reset)
	fmt.Fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    ⏱️   %s-t%s          show connection close events with duration\n", yellow, reset)
	fmt.Fprintf(e, "    🔄  %s-U%s          show TCP state update events %s(ESTABLISHED, FIN_WAIT, ...)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    👤  %s-u%s          print owning user of each connection\n", yellow, reset)
	fmt.Fprintf(e, "    🔍  %s-r%s          reverse DNS lookup for remote IPs %s(async, cached)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    4️⃣   %s-4%s          IPv4 connections only\n", yellow, reset)
	fmt.Fprintf(e, "    6️⃣   %s-6%s          IPv6 connections only\n", yellow, reset)
	fmt.Fprintf(e, "    📤  %s-O%s          outbound connections only %s(hide inbound/unknown)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset)
	fmt.Fprintf(e, "    📝  %s-o%s %sFILE%s      write output to FILE instead of stdout\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    🎯  %s-p%s %sPID%s       trace PIDs and their descendants %s(comma-separate for multiple)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "\n  %sOutput columns:%s\n", bold, reset)
	fmt.Fprintf(e, "    PID  COMM         PROTO  SRC_IP:PORT              %s→%s  DST_IP:PORT\n", cyan, reset)
	fmt.Fprintf(e, "    %s→%s outbound  %s←%s inbound  %s↔%s unknown direction\n", cyan, reset, cyan, reset, cyan, reset)
	fmt.Fprintf(e, "    %s⇒%s TCP state update (with -U)   %s×%s connection closed (with -t)\n\n", magenta, reset, yellow, reset)
	fmt.Fprintf(e, "  %sExamples:%s\n", bold, reset)
	fmt.Fprintf(e, "    %s# trace all connections system-wide%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-net %s-ctu%s\n\n", green, reset)
	fmt.Fprintf(e, "    %s# trace connections made by a command%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-net %s-ctr%s curl https://example.com\n\n", green, reset)
	fmt.Fprintf(e, "    %s# watch all nginx worker connections%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-net %s-p%s $(pgrep nginx | paste -sd,)\n\n", green, reset)
	fmt.Fprintf(e, "    %s# log everything to a file%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-net %s-Qo%s /var/log/connections.log\n\n", green, reset)
	os.Exit(1)
}
