//go:build linux

// proc-trace-tls — capture plaintext TLS traffic via ftrace uprobes on OpenSSL/GnuTLS
//
// Attaches uprobes to SSL_read / SSL_write (and their _ex variants) in libssl.so
// using the kernel's ftrace uprobe interface (/sys/kernel/debug/tracing).
// Also uprobes SSL_get_servername to capture SNI hostnames.
// Falls back to /proc/<pid>/net/tcp[6] for IP when SNI is unavailable.
// No eBPF. No ptrace. No kernel modules. Just ftrace and /proc.
//
// Requires root or CAP_SYS_ADMIN + CAP_DAC_OVERRIDE (for debugfs).
//
// Usage: proc-trace-tls [-achqQsvR] [-l LIB] [-o FILE] [-p PID[,PID,...]]
package tlstrace

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─── Constants ────────────────────────────────────────────────────────────────

var version = "dev"

const (
	tracingBase    = "/sys/kernel/debug/tracing"
	uprobeEvents   = tracingBase + "/uprobe_events"
	tracePipe      = tracingBase + "/trace_pipe"
	traceOn        = tracingBase + "/tracing_on"
	currentTracer  = tracingBase + "/current_tracer"
)

// probeTargets are the symbols we uprobe in libssl.
var probeTargets = []struct {
	symbol    string
	isRet     bool
	dir       string // "read", "write", or "sni"
	extraArgs string // extra ftrace argument spec appended to the probe line
	filter    string // written to the uprobe's filter file after enabling (empty = no filter)
}{
	{"SSL_read", false, "read", "", ""},
	{"SSL_read", true, "read", "", ""},
	{"SSL_write", false, "write", "", ""},
	{"SSL_read_ex", false, "read", "", ""},
	{"SSL_write_ex", false, "write", "", ""},
	// SSL_get_servername returns const char* — capture as uretprobe string (server-side)
	{"SSL_get_servername", true, "sni", "+0($retval):string", ""},
	// SSL_ctrl(ssl, cmd=55, 0, hostname) is called by SSL_set_tlsext_host_name on the client side.
	// Capture cmd (%si) and the hostname string (+0(%cx)) as named fields; filter to cmd==55.
	{"SSL_ctrl", false, "sni", "cmd=%si:u64 sni=+0(%cx):string", "cmd==55"},
}

// ─── Options ──────────────────────────────────────────────────────────────────

var (
	watchPIDs   []int
	libSSLPath  string
	outFile     string
	colorForce  bool
	colorMode   bool
	quietMode   bool
	showErrors       = true
	sizeOnly    bool
	verbose     bool
	noReverseDNS bool
	out         io.Writer = os.Stdout
)

// ─── Per-PID SNI cache ────────────────────────────────────────────────────────

// sniCache maps pid → most-recently-seen SNI hostname
var (
	sniMu    sync.RWMutex
	sniCache = make(map[int]string)
)

func setSNI(pid int, host string) {
	sniMu.Lock()
	sniCache[pid] = host
	sniMu.Unlock()
}

func getSNI(pid int) string {
	sniMu.RLock()
	defer sniMu.RUnlock()
	return sniCache[pid]
}

// ─── Output ───────────────────────────────────────────────────────────────────

var mu sync.Mutex

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

// ─── libssl discovery ─────────────────────────────────────────────────────────

// resolveLib resolves a library path to its real path, following all symlinks.
// The kernel's uprobe mechanism does NOT follow symlinks, so we must pass the
// real (non-symlink) path or the uprobe will be attached to the wrong inode.
func resolveLib(path string) string {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return real
}

func findLibSSL() (string, error) {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib64/libssl.so.3",
		"/lib64/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.1.1",
	}

	if len(watchPIDs) > 0 {
		for _, pid := range watchPIDs {
			if lib := libFromMaps(pid); lib != "" {
				return lib, nil
			}
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return resolveLib(c), nil
		}
	}
	return "", fmt.Errorf("libssl.so not found; use -l to specify")
}

func libFromMaps(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "libssl") {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				lib := fields[5]
				if _, err := os.Stat(lib); err == nil {
					return resolveLib(lib)
				}
			}
		}
	}
	return ""
}

// ─── Remote host resolution ───────────────────────────────────────────────────

// remoteHost returns SNI (preferred) or IP:port from /proc/net/tcp[6].
func remoteHost(pid int) string {
	if sni := getSNI(pid); sni != "" {
		return sni
	}
	return remoteFromProcNet(pid)
}

// remoteFromProcNet reads /proc/<pid>/net/tcp and tcp6, returns "IP:port" of
// the first ESTABLISHED (state=01) connection whose local port is >= 1024
// (i.e. not a server listener). Returns empty string on failure.
func remoteFromProcNet(pid int) string {
	for _, proto := range []string{"tcp6", "tcp"} {
		path := fmt.Sprintf("/proc/%d/net/%s", pid, proto)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			state := fields[3]
			if state != "01" { // 01 = ESTABLISHED
				continue
			}
			remHex := fields[2] // "XXXXXXXX:PPPP"
			addr := parseHexAddr(remHex, proto == "tcp6")
			if addr != "" {
				return addr
			}
		}
	}
	return ""
}

// parseHexAddr converts a kernel hex address "AABBCCDD:PPPP" (IPv4 little-endian)
// or "AABBCCDDAABBCCDDAABBCCDDAABBCCDD:PPPP" (IPv6) into "ip:port".
func parseHexAddr(hexAddr string, isV6 bool) string {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	portHex := parts[1]
	addrHex := parts[0]

	portN, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return ""
	}
	port := int(portN)
	if port == 0 {
		return ""
	}

	var ip net.IP
	if !isV6 {
		// IPv4: 4 bytes little-endian
		b, err := hex.DecodeString(addrHex)
		if err != nil || len(b) != 4 {
			return ""
		}
		addr32 := binary.LittleEndian.Uint32(b)
		ip = net.IPv4(byte(addr32), byte(addr32>>8), byte(addr32>>16), byte(addr32>>24))
	} else {
		// IPv6: 16 bytes, stored as four little-endian 32-bit words
		b, err := hex.DecodeString(addrHex)
		if err != nil || len(b) != 16 {
			return ""
		}
		// reverse each 4-byte group
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
		ip = net.IP(b)
		// skip loopback / link-local
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return ""
		}
	}

	if ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}

	if !noReverseDNS {
		if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
			host := strings.TrimSuffix(names[0], ".")
			return fmt.Sprintf("%s:%d", host, port)
		}
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// ─── Symbol offset ────────────────────────────────────────────────────────────

func symbolOffset(libPath, sym string) (uint64, error) {
	data, err := runCmd("nm", "-D", "--defined-only", libPath)
	if err != nil {
		data, err = runCmd("objdump", "-T", libPath)
		if err != nil {
			return 0, fmt.Errorf("nm/objdump not available: %v", err)
		}
	}

	re := regexp.MustCompile(`(?m)^([0-9a-f]+)\s+(?:[0-9a-f]+\s+)?\S+\s+` + regexp.QuoteMeta(sym) + `\b`)
	m := re.FindStringSubmatch(string(data))
	if m == nil {
		re2 := regexp.MustCompile(`(?m)^([0-9a-f]+)\s+\S\s+` + regexp.QuoteMeta(sym) + `\b`)
		m = re2.FindStringSubmatch(string(data))
	}
	if m == nil {
		return 0, fmt.Errorf("symbol %s not found in %s", sym, libPath)
	}
	offset, err := strconv.ParseUint(m[1], 16, 64)
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func runCmd(name string, args ...string) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	pid, err := syscall.ForkExec(mustLookPath(name), append([]string{name}, args...),
		&syscall.ProcAttr{
			Files: []uintptr{uintptr(os.Stdin.Fd()), w.Fd(), w.Fd()},
		})
	w.Close()
	if err != nil {
		return nil, fmt.Errorf("exec %s: %v", name, err)
	}

	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	var ws syscall.WaitStatus
	syscall.Wait4(pid, &ws, 0, nil)
	return buf, nil
}

func mustLookPath(name string) string {
	for _, d := range []string{"/usr/bin", "/bin", "/usr/local/bin", "/sbin", "/usr/sbin"} {
		p := filepath.Join(d, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/" + name
}

// ─── Uprobe management ────────────────────────────────────────────────────────

type probeEntry struct {
	name   string
	isRet  bool
	dir    string
	symbol string
}

var registeredProbes []probeEntry

func registerUprobes(libPath string) error {
	seen := map[string]bool{}

	for _, t := range probeTargets {
		offset, err := symbolOffset(libPath, t.symbol)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  skipping %s: %v\n", t.symbol, err)
			}
			continue
		}

		prefix := "p"
		if t.isRet {
			prefix = "r"
		}
		name := fmt.Sprintf("tls_%s_%s", t.dir, t.symbol)
		if t.isRet {
			name += "_ret"
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		// Remove any stale probe with this name (e.g. from a previous run killed without cleanup).
		// Must disable before removing, and use the full group/name format.
		enablePath := fmt.Sprintf("%s/events/uprobes/%s/enable", tracingBase, name)
		_ = os.WriteFile(enablePath, []byte("0"), 0)
		_ = appendToFile(uprobeEvents, "-:uprobes/"+name)

		line := fmt.Sprintf("%s:%s %s:0x%x", prefix, name, libPath, offset)
		if t.extraArgs != "" {
			line += " " + t.extraArgs
		}
		if err := appendToFile(uprobeEvents, line); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  uprobe %s: %v\n", name, err)
			}
			continue
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "  registered: %s @ 0x%x\n", name, offset)
		}

		enablePath = fmt.Sprintf("%s/events/uprobes/%s/enable", tracingBase, name)
		if err := os.WriteFile(enablePath, []byte("1"), 0); err != nil && verbose {
			fmt.Fprintf(os.Stderr, "  enable %s: %v\n", name, err)
		}

		if t.filter != "" {
			filterPath := fmt.Sprintf("%s/events/uprobes/%s/filter", tracingBase, name)
			if err := os.WriteFile(filterPath, []byte(t.filter), 0); err != nil && verbose {
				fmt.Fprintf(os.Stderr, "  filter %s: %v\n", name, err)
			}
		}

		registeredProbes = append(registeredProbes, probeEntry{
			name: name, isRet: t.isRet, dir: t.dir, symbol: t.symbol,
		})
	}

	if len(registeredProbes) == 0 {
		return fmt.Errorf("no uprobes registered — is OpenSSL installed?")
	}
	return nil
}

func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, content)
	return err
}

func cleanupUprobes() {
	for _, p := range registeredProbes {
		enablePath := fmt.Sprintf("%s/events/uprobes/%s/enable", tracingBase, p.name)
		os.WriteFile(enablePath, []byte("0"), 0)
		appendToFile(uprobeEvents, "-:uprobes/"+p.name)
	}
}

// ─── Trace event parsing ──────────────────────────────────────────────────────

// Normal trace line (older kernels):
//   curl-12345 [003] d... 123.456789: tls_write_SSL_write: (0x7f...)
// Normal trace line (kernel 6.x — includes (TGID) between pid and cpu):
//   curl-12345 (12345) [003] DBZff 123.456789: tls_write_SSL_write: (0x7f...)
// SNI uretprobe trace line:
//   curl-12345 [003] d... 123.456789: tls_sni_SSL_get_servername: (0x7f...->0x0) arg1="api.github.com"
var (
	traceRe = regexp.MustCompile(`^\s*(\S+)-(\d+)\s+(?:\(\S+\)\s+)?\[\d+\].*\s+([\d.]+):\s+(tls_\w+)`)
	sniRe   = regexp.MustCompile(`(?:arg1|sni)="([^"]*)"`)
)

type tlsEvent struct {
	comm      string
	pid       int
	ts        float64
	probeName string
	dir       string
	sni       string // non-empty only for dir=="sni"
}

func parseLine(line string) (*tlsEvent, bool) {
	m := traceRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	pid, _ := strconv.Atoi(m[2])
	ts, _ := strconv.ParseFloat(m[3], 64)

	dir := "?"
	var sni string
	if strings.Contains(m[4], "_sni") {
		dir = "sni"
		if sm := sniRe.FindStringSubmatch(line); sm != nil {
			sni = sm[1]
		}
	} else if strings.Contains(m[4], "_read") {
		dir = "read"
	} else if strings.Contains(m[4], "_write") {
		dir = "write"
	}

	return &tlsEvent{
		comm:      m[1],
		pid:       pid,
		ts:        ts,
		probeName: m[4],
		dir:       dir,
		sni:       sni,
	}, true
}

func isWatched(pid int) bool {
	if len(watchPIDs) == 0 {
		return true
	}
	for _, w := range watchPIDs {
		if pid == w {
			return true
		}
	}
	return false
}

func procComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimRight(string(data), "\n")
}

// ─── Event output ─────────────────────────────────────────────────────────────

var counter int64
var connSeen = make(map[string]bool)

func printEvent(ev *tlsEvent) {
	mu.Lock()
	defer mu.Unlock()

	// SNI events update the per-PID cache and are otherwise silent
	if ev.dir == "sni" {
		if ev.sni != "" {
			setSNI(ev.pid, ev.sni)
		}
		return
	}

	host := remoteHost(ev.pid)

	// One line per (pid, host) connection — suppress duplicate read/write events
	key := fmt.Sprintf("%d|%s", ev.pid, host)
	if connSeen[key] {
		return
	}
	connSeen[key] = true

	counter++

	ts := time.Unix(0, int64(ev.ts*1e9)).Format("15:04:05.000")

	var dirStr, dirClr string
	if ev.dir == "write" {
		dirStr = "TX"
		dirClr = "33"
	} else {
		dirStr = "RX"
		dirClr = "36"
	}

	sym := ev.probeName
	sym = strings.TrimPrefix(sym, "tls_read_")
	sym = strings.TrimPrefix(sym, "tls_write_")
	sym = strings.TrimSuffix(sym, "_ret")

	pidStr := clr("33", strconv.Itoa(ev.pid))
	commStr := clr("96", ev.comm)
	dirFmt := clr(dirClr, dirStr)
	tsStr := clr("2", ts)
	symStr := clr("2", sym)

	var hostStr string
	if host != "" {
		hostStr = "  " + clr("35", host)
	}

	fmt.Fprintf(out, "%s %s %s %s %s%s\n",
		tsStr, pidStr, commStr, dirFmt, symStr, hostStr)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func Main() {
	args := os.Args[1:]

	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			fatalf("unexpected argument: %s", a)
		}
		for _, ch := range a[1:] {
			switch ch {
			case 'c':
				colorForce = true
			case 'h':
				usage()
			case 'l':
				if i+1 >= len(args) {
					fatal("-l requires a path")
				}
				i++
				libSSLPath = args[i]
			case 'o':
				if i+1 >= len(args) {
					fatal("-o requires a path")
				}
				i++
				outFile = args[i]
			case 'p':
				if i+1 >= len(args) {
					fatal("-p requires a PID list")
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
					watchPIDs = append(watchPIDs, pid)
				}
			case 'q':
				quietMode = true
			case 'Q':
				showErrors = false
			case 'R':
				noReverseDNS = true
			case 's':
				sizeOnly = true
			case 'v':
				verbose = true
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

	if libSSLPath == "" {
		var err error
		libSSLPath, err = findLibSSL()
		if err != nil {
			fatalf("%v\nHint: install openssl or use -l /path/to/libssl.so", err)
		}
	}

	if !quietMode {
		fmt.Fprintf(os.Stderr, "%s\n", clr("96", "proc-trace-tls "+version))
		fmt.Fprintf(os.Stderr, "  lib : %s\n", clr("2", libSSLPath))
		if len(watchPIDs) > 0 {
			pidStrs := make([]string, len(watchPIDs))
			for i, p := range watchPIDs {
				pidStrs[i] = strconv.Itoa(p)
			}
			fmt.Fprintf(os.Stderr, "  pids: %s\n", clr("33", strings.Join(pidStrs, ",")))
		} else {
			fmt.Fprintf(os.Stderr, "  pids: %s\n", clr("2", "all"))
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	if err := os.WriteFile(traceOn, []byte("1"), 0); err != nil {
		fatalf("enable tracing: %v\nAre you root? Is debugfs mounted at %s?", err, tracingBase)
	}

	// Switch to the no-op tracer so the ring buffer isn't flooded with
	// function-tracer events, which would drown out or drop uprobe hits.
	if err := os.WriteFile(currentTracer, []byte("nop"), 0); err != nil && verbose {
		fmt.Fprintf(os.Stderr, "  warning: could not set current_tracer to nop: %v\n", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Registering uprobes on %s...\n", libSSLPath)
	}
	if err := registerUprobes(libSSLPath); err != nil {
		fatalf("%v", err)
	}
	if !quietMode {
		fmt.Fprintf(os.Stderr, "Watching %d probe(s). Press Ctrl-C to stop.\n\n", len(registeredProbes))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !quietMode {
			fmt.Fprintf(os.Stderr, "\n\ncaptured %d TLS events\n", counter)
		}
		cleanupUprobes()
		os.Exit(0)
	}()

	f, err := os.Open(tracePipe)
	if err != nil {
		cleanupUprobes()
		fatalf("open trace_pipe: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		ev, ok := parseLine(line)
		if !ok {
			continue
		}
		if !isWatched(ev.pid) {
			continue
		}
		printEvent(ev)
	}
}

// ─── Error helpers ────────────────────────────────────────────────────────────

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "proc-trace-tls: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "proc-trace-tls: "+msg)
	os.Exit(1)
}

func usage() {
	const (
		bold   = "\033[1m"
		dim    = "\033[2m"
		reset  = "\033[0m"
		cyan   = "\033[36m"
		yellow = "\033[33m"
		green  = "\033[32m"
	)
	e := os.Stderr
	fmt.Fprintf(e, "\n  %s🔒 proc-trace-tls%s %s%s%s — plaintext TLS traffic interceptor for Linux\n\n", bold+cyan, reset, dim, version, reset)
	fmt.Fprintf(e, "  %sUsage:%s\n", bold, reset)
	fmt.Fprintf(e, "    proc-trace-tls %s[flags]%s\n\n", dim, reset)
	fmt.Fprintf(e, "  %sFlags:%s\n", bold, reset)
	fmt.Fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    🔗  %s-l%s %sLIB%s      path to libssl.so %s(auto-detected if omitted)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    📝  %s-o%s %sFILE%s     log output to FILE instead of stdout\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    🎯  %s-p%s %sPID%s      trace only PID(s) %s(comma-separated)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    🤫  %s-q%s          suppress startup messages\n", yellow, reset)
	fmt.Fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset)
	fmt.Fprintf(e, "    🚫  %s-R%s          skip reverse DNS %s(show raw IPs)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    📊  %s-s%s          event summary only\n", yellow, reset)
	fmt.Fprintf(e, "    🔍  %s-v%s          verbose probe registration\n", yellow, reset)
	fmt.Fprintf(e, "\n  %sExamples:%s\n", bold, reset)
	fmt.Fprintf(e, "    sudo proc-trace-tls\n\n")
	fmt.Fprintf(e, "    sudo proc-trace-tls %s-p%s $(pgrep curl)\n\n", green, reset)
	fmt.Fprintf(e, "    sudo proc-trace-tls %s-R%s  %s# raw IPs, no DNS%s\n\n", green, reset, dim, reset)
	os.Exit(1)
}
