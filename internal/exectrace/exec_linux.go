//go:build linux

// proc-trace-exec — trace exec() calls system-wide via Linux proc connector
//
// Requires CONFIG_CONNECTOR=y and CONFIG_PROC_EVENTS=y
// Requires root or CAP_NET_ADMIN
//
// Usage: proc-trace-exec [-cdeflqQtu] [-o FILE] [-p PID[,PID,...] | CMD...]
package exectrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// ─── Netlink / proc connector constants ──────────────────────────────────────

const (
	netlinkConnector  = 11
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procCnMcastIgnore = 2

	procEventNone = uint32(0x00000000)
	procEventFork = uint32(0x00000001)
	procEventExec = uint32(0x00000002)
	procEventExit = uint32(0x80000000)

	nlmsgHdrSize = 16 // sizeof(struct nlmsghdr)
	cnMsgSize    = 20 // sizeof(struct cn_msg): 4+4+4+4+2+2
	procEvtHdr   = 16 // what(4)+cpu(4)+ts(8)
)

// ─── Proc database ───────────────────────────────────────────────────────────

type pidEntry struct {
	depth   int
	startNs uint64
	cmdline string // first arg, for exit line
}

var (
	mu    sync.Mutex
	pidDB = make(map[int32]*pidEntry)
)

// ─── Global options ───────────────────────────────────────────────────────────

var version = "dev"

var (
	watchPIDs  []int32   // empty until parsed; default [1] = global mode
	showCwd    bool
	showEnv    bool
	flatMode   bool
	fullPath   bool
	showArgs   = true
	showErrors = true
	showExit   bool
	showUser   bool
	colorMode  bool // auto-detected or forced with -c
	colorForce bool
	out        io.Writer = os.Stdout
)

// ─── Color helpers ────────────────────────────────────────────────────────────

// clr wraps s in an ANSI color code when color mode is on.
func clr(code, s string) string {
	if !colorMode || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// isTerminal reports whether f looks like an interactive terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// isWatchRoot reports whether pid is one of the watched root PIDs.
func isWatchRoot(pid int32) bool {
	for _, w := range watchPIDs {
		if pid == w {
			return true
		}
	}
	return false
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
			case 'd':
				showCwd = true
			case 'e':
				showEnv = true
			case 'f':
				flatMode = true
			case 'l':
				fullPath = true
			case 'q':
				showArgs = false
			case 'Q':
				showErrors = false
			case 't':
				showExit = true
			case 'u':
				showUser = true
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

	if len(watchPIDs) == 0 {
		watchPIDs = []int32{1} // default: global mode (trace everything)
	}

	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fatalf("open %s: %v", outFile, err)
		}
		defer f.Close()
		out = f
	}

	// Auto-detect color: on when stdout is a tty and NO_COLOR is not set.
	if colorForce {
		colorMode = true
	} else if os.Getenv("NO_COLOR") == "" {
		if f, ok := out.(*os.File); ok {
			colorMode = isTerminal(f)
		}
	}

	// Build netlink socket
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, netlinkConnector)
	if err != nil {
		fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: cnIdxProc,
		Pid:    uint32(os.Getpid()),
	}
	if err := syscall.Bind(fd, sa); err != nil {
		fatalf("bind: %v", err)
	}

	if err := sendMcastOp(fd, procCnMcastListen); err != nil {
		fatalf("subscribe: %v", err)
	}

	// CMD mode: fork the command and trace only its subtree.
	if len(cmdArgs) > 0 {
		watchPIDs = []int32{int32(os.Getpid())}
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fatalf("exec %s: %v", cmdArgs[0], err)
		}
		go func() {
			cmd.Wait()
			sendMcastOp(fd, procCnMcastIgnore) //nolint
			os.Exit(0)
		}()
	}

	// Event loop
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fatalf("recvfrom: %v", err)
		}
		dispatchNlMsg(buf[:n])
	}
}

// ─── Netlink helpers ──────────────────────────────────────────────────────────

func sendMcastOp(fd int, op uint32) error {
	var buf [nlmsgHdrSize + cnMsgSize + 4]byte
	le := binary.LittleEndian

	total := uint32(len(buf))
	le.PutUint32(buf[0:], total)
	le.PutUint16(buf[4:], syscall.NLMSG_DONE)
	le.PutUint16(buf[6:], 0)
	le.PutUint32(buf[8:], 0)
	le.PutUint32(buf[12:], uint32(os.Getpid()))

	le.PutUint32(buf[16:], cnIdxProc)
	le.PutUint32(buf[20:], cnValProc)
	le.PutUint32(buf[24:], 0)
	le.PutUint32(buf[28:], 0)
	le.PutUint16(buf[32:], 4)
	le.PutUint16(buf[34:], 0)

	le.PutUint32(buf[36:], op)

	to := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, buf[:], 0, to)
}

func dispatchNlMsg(data []byte) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return
	}
	for _, msg := range msgs {
		d := msg.Data
		if len(d) < cnMsgSize+procEvtHdr {
			continue
		}
		idx := binary.LittleEndian.Uint32(d[0:])
		val := binary.LittleEndian.Uint32(d[4:])
		if idx != cnIdxProc || val != cnValProc {
			continue
		}
		what := binary.LittleEndian.Uint32(d[cnMsgSize:])
		tsNs := binary.LittleEndian.Uint64(d[cnMsgSize+8:])
		evData := d[cnMsgSize+procEvtHdr:]

		switch what {
		case procEventExec:
			handleExec(evData, tsNs)
		case procEventExit:
			handleExit(evData, tsNs)
		}
	}
}

// ─── Event handlers ───────────────────────────────────────────────────────────

func handleExec(data []byte, tsNs uint64) {
	if len(data) < 8 {
		return
	}
	pid := int32(binary.LittleEndian.Uint32(data[0:]))

	d := pidDepth(pid)
	if d < 0 {
		return
	}

	mu.Lock()
	ent, exists := pidDB[pid]
	if !exists {
		ent = &pidEntry{}
		pidDB[pid] = ent
	}

	if showExit && exists && ent.cmdline != "" {
		line := buildExecedLine(ent, pid)
		mu.Unlock()
		fmt.Fprintln(out, line)
		mu.Lock()
	}

	ent.depth = d
	ent.startNs = tsNs
	ent.cmdline = readFirstArg(pid)
	mu.Unlock()

	printExec(pid, d, tsNs)
}

func handleExit(data []byte, tsNs uint64) {
	if len(data) < 24 {
		return
	}
	pid := int32(binary.LittleEndian.Uint32(data[0:]))
	exitCode := binary.LittleEndian.Uint32(data[8:])

	mu.Lock()
	ent, ok := pidDB[pid]
	if ok {
		delete(pidDB, pid)
	}
	mu.Unlock()

	if !ok || !showExit {
		return
	}

	indent := indentStr(ent.depth)
	elapsed := float64(tsNs-ent.startNs) / 1e9

	var exitStr string
	if exitCode&0x7f == 0 { // WIFEXITED
		code := int((exitCode >> 8) & 0xff)
		if code == 0 {
			exitStr = clr("32", "status=0")
		} else {
			exitStr = clr("31", fmt.Sprintf("status=%d", code))
		}
	} else { // signaled
		exitStr = clr("91", fmt.Sprintf("signal=%s", sigName(int(exitCode&0x7f))))
	}

	fmt.Fprintf(out, "%s%s%s %s exited %s %s\n",
		indent,
		clr("33", strconv.Itoa(int(pid))),
		clr("31", "-"),
		clr("2", shQuote(ent.cmdline)),
		exitStr,
		clr("36", fmt.Sprintf("time=%.3fs", elapsed)),
	)
}

// ─── Output formatting ────────────────────────────────────────────────────────

func printExec(pid int32, depth int, tsNs uint64) {
	indent := indentStr(depth)

	var sb strings.Builder
	sb.WriteString(indent)
	sb.WriteString(clr("33", strconv.Itoa(int(pid))))
	if showExit {
		sb.WriteString(clr("32", "+"))
	}

	if showUser {
		name := procUser(pid)
		if name == "root" {
			sb.WriteString(clr("91", " <"+name+">"))
		} else {
			sb.WriteString(clr("92", " <"+name+">"))
		}
	}

	sb.WriteByte(' ')

	if showCwd {
		cwd := procCwd(pid)
		sb.WriteString(clr("35", shQuote(cwd)))
		sb.WriteString(clr("2", " % "))
	}

	argv := readCmdline(pid)
	if len(argv) == 0 {
		comm := readComm(pid)
		if comm == "" {
			return
		}
		sb.WriteString(clr("2", "["+comm+"]"))
	} else {
		var cmd string
		if fullPath {
			if exe := readExe(pid); exe != "" {
				cmd = shQuote(exe)
			} else {
				cmd = shQuote(argv[0])
			}
		} else {
			cmd = shQuote(argv[0])
		}
		sb.WriteString(clr("96", cmd))
		if showArgs && len(argv) > 1 {
			for _, arg := range argv[1:] {
				sb.WriteByte(' ')
				sb.WriteString(clr("2", shQuote(arg)))
			}
		}
	}

	if showEnv {
		env := readEnviron(pid)
		sb.WriteString("\n  ")
		for _, e := range env {
			sb.WriteByte(' ')
			eq := strings.IndexByte(e, '=')
			if eq >= 0 {
				sb.WriteString(clr("2", shQuote(e[:eq])+"="+shQuote(e[eq+1:])))
			} else {
				sb.WriteString(clr("2", shQuote(e)))
			}
		}
	}

	fmt.Fprintln(out, sb.String())
}

func buildExecedLine(ent *pidEntry, pid int32) string {
	return fmt.Sprintf("%s%s%s %s execed",
		indentStr(ent.depth),
		clr("33", strconv.Itoa(int(pid))),
		clr("31", "-"),
		clr("2", shQuote(ent.cmdline)),
	)
}

func indentStr(depth int) string {
	if flatMode || depth <= 0 {
		return ""
	}
	return strings.Repeat("  ", depth)
}

// ─── Depth / ancestry ─────────────────────────────────────────────────────────

// pidDepth returns the tree depth of pid relative to the nearest watchPID,
// or -1 if pid is not a descendant of any watched root.
func pidDepth(pid int32) int {
	if isWatchRoot(pid) {
		return 0
	}
	ppid := statPPID(pid)
	if ppid < 0 {
		runtimeErr("proc-trace-exec: process vanished before we found its parent: pid %d", pid)
		return -1
	}
	if ppid == 0 {
		// Reached the top of the process tree without hitting a watch root.
		return -1
	}
	if isWatchRoot(ppid) {
		return 0
	}

	// Check depth cache
	mu.Lock()
	if ent, ok := pidDB[ppid]; ok {
		d := ent.depth
		mu.Unlock()
		return d + 1
	}
	mu.Unlock()

	// Recurse up the parent chain
	d := pidDepth(ppid)
	if d < 0 {
		return -1
	}
	return d + 1
}

// statPPID reads the ppid from /proc/pid/stat (handles parens in comm).
// Returns the ppid (0 = parent of PID 1), or -1 on read error.
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

// ─── /proc helpers ────────────────────────────────────────────────────────────

func readCmdline(pid int32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	data = bytes.TrimRight(data, "\x00")
	parts := bytes.Split(data, []byte{0})
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		result = append(result, string(p))
	}
	return result
}

func readFirstArg(pid int32) string {
	argv := readCmdline(pid)
	if len(argv) == 0 {
		return readComm(pid)
	}
	return filepath.Base(argv[0])
}

func readExe(pid int32) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exe
}

func readComm(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n")
}

func procCwd(pid int32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		if os.IsPermission(err) {
			return "EACCES"
		}
		return "EUNKNOWN"
	}
	return cwd
}

func readEnviron(pid int32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	data = bytes.TrimRight(data, "\x00")
	parts := bytes.Split(data, []byte{0})
	env := make([]string, 0, len(parts))
	for _, p := range parts {
		env = append(env, string(p))
	}
	return env
}

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

// ─── Shell quoting ────────────────────────────────────────────────────────────

func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		if c <= ' ' || strings.ContainsRune("`^#*[]=|\\?${}()'\"<>&;\x7f", c) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	var sb strings.Builder
	sb.WriteByte('\'')
	for _, c := range s {
		if c == '\'' {
			sb.WriteString("'\\''")
		} else if c == '\n' {
			sb.WriteString("'$'\\n''")
		} else {
			sb.WriteRune(c)
		}
	}
	sb.WriteByte('\'')
	return sb.String()
}

// ─── Signal names ─────────────────────────────────────────────────────────────

func sigName(sig int) string {
	names := map[int]string{
		1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
		5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
		9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
		13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 17: "SIGCHLD",
		18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP", 21: "SIGTTIN",
		22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ",
		26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO",
		30: "SIGPWR", 31: "SIGSYS",
	}
	if name, ok := names[sig]; ok {
		return name
	}
	return fmt.Sprintf("SIG%d", sig)
}

// ─── Error helpers ────────────────────────────────────────────────────────────

func runtimeErr(f string, args ...any) {
	if showErrors {
		fmt.Fprintf(os.Stderr, f+"\n", args...)
	}
}

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "proc-trace-exec: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "proc-trace-exec: "+msg)
	os.Exit(1)
}

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
	fmt.Fprintf(e, "\n  %s🔍 proc-trace-exec%s %s%s%s — system-wide exec() tracer for Linux\n\n", bold+cyan, reset, dim, version, reset)
	fmt.Fprintf(e, "  %sUsage:%s\n", bold, reset)
	fmt.Fprintf(e, "    proc-trace-exec %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n", dim, reset, yellow, reset)
	fmt.Fprintf(e, "  %sFlags:%s\n", bold, reset)
	fmt.Fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    📁  %s-d%s          print cwd of each process\n", yellow, reset)
	fmt.Fprintf(e, "    🌿  %s-e%s          print environment variables\n", yellow, reset)
	fmt.Fprintf(e, "    ⬜  %s-f%s          flat output %s(no indentation)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    🔗  %s-l%s          print full executable path\n", yellow, reset)
	fmt.Fprintf(e, "    📝  %s-o%s %sFILE%s      log output to FILE instead of stdout\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    🎯  %s-p%s %sPID%s       trace descendants of PID %s(repeat or comma-separate for multiple)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    🤫  %s-q%s          suppress arguments\n", yellow, reset)
	fmt.Fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset)
	fmt.Fprintf(e, "    ⏱️   %s-t%s          show exit status + timing\n", yellow, reset)
	fmt.Fprintf(e, "    👤  %s-u%s          print owning user\n", yellow, reset)
	fmt.Fprintf(e, "\n  %sExamples:%s\n", bold, reset)
	fmt.Fprintf(e, "    %s# trace a command and all its children%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-exec %s-ct%s sh -c %s'make'%s\n\n", green, reset, magenta, reset)
	fmt.Fprintf(e, "    %s# watch all nginx worker processes%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-exec %s-p%s $(pgrep nginx | paste -sd,)\n\n", green, reset)
	fmt.Fprintf(e, "    %s# log everything quietly to a file%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-exec %s-Qo%s /var/log/execs.log\n\n", green, reset)
	os.Exit(1)
}
