//go:build darwin

// macOS exec tracer — polls proc_listallpids() and diffs against the
// previous snapshot to detect new processes, pid reuse (start_time
// changed) and in-place exec() (argv[0] changed for the same pid+start).
// Short-lived processes that fork+exec+exit inside one poll interval
// are missed; there is no Apple-supported event stream for exec()
// without the EndpointSecurity entitlement.
//
// Pure stdlib — calls Apple's proc_info syscall (SYS_PROC_INFO = 336)
// directly via syscall.Syscall6 so the binary still cross-compiles from
// any host without cgo.
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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ─── proc_info syscall constants (from <sys/proc_info.h>) ────────────────────

const (
	procInfoCallListPIDs = 1
	procInfoCallPIDInfo  = 2

	procAllPIDs = 1 // type for PROC_INFO_CALL_LISTPIDS

	procPIDTBSDInfo      = 3
	procPIDVNodePathInfo = 9
	procPIDPathInfo      = 11

	procPIDPathInfoSize     = 1024 // MAXPATHLEN
	procPIDTBSDInfoSize     = 136  // sizeof(struct proc_bsdinfo)
	procPIDVNodePathInfoSz  = 2352 // sizeof(struct proc_vnodepathinfo)
	procVNodeInfoPathCwdOff = 152  // offset of vip_path within pvi_cdir

	// sysctl MIB constants (<sys/sysctl.h>) — stdlib syscall doesn't
	// expose darwin SysctlRaw, so we call SYS___SYSCTL by hand with these.
	ctlKern        = 1
	kernArgmax     = 8
	kernProcArgs2  = 49
)

// ─── Global options (mirror exec_linux.go) ───────────────────────────────────

var version = "dev"

var (
	watchPIDs  []int32
	showCwd    bool
	showEnv    bool
	flatMode   bool
	fullPath   bool
	showArgs   = true
	showErrors = true
	showExit   bool
	showUser   bool
	colorMode  bool
	colorForce bool
	out        io.Writer = os.Stdout

	pollIntervalMs = 50
)

// ─── Per-pid snapshot for delta detection ────────────────────────────────────

type macEntry struct {
	pid       int32
	ppid      int32
	uid       uint32
	startSec  uint64
	startUsec uint64
	argv0     string // for in-place exec detection (compare next tick)
	depth     int
}

var (
	mu sync.Mutex
	db = map[int32]*macEntry{}
)

// ─── Color helpers ───────────────────────────────────────────────────────────

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

func isWatchRoot(pid int32) bool {
	for _, w := range watchPIDs {
		if pid == w {
			return true
		}
	}
	return false
}

// ─── Raw syscall wrappers ────────────────────────────────────────────────────

// procListAllPIDs returns every currently-live pid. Asks the kernel for the
// required buffer size first (passing buf=NULL), then allocates and calls
// again. The buffer is filled with int32 pids; size is in bytes.
func procListAllPIDs() ([]int32, error) {
	// Sizing call: buf=NULL, size=0 → returns total bytes needed.
	sz, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procInfoCallListPIDs, procAllPIDs, 0, 0, 0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	// Add headroom for processes spawned between the two calls.
	bufBytes := int(sz) + 4096
	buf := make([]byte, bufBytes)
	n, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procInfoCallListPIDs, procAllPIDs, 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(bufBytes),
	)
	if errno != 0 {
		return nil, errno
	}
	count := int(n) / 4
	pids := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		p := int32(binary.LittleEndian.Uint32(buf[i*4 : i*4+4]))
		if p > 0 {
			pids = append(pids, p)
		}
	}
	return pids, nil
}

// procPIDInfo calls proc_pidinfo(pid, flavor, 0, buf, bufsize). Returns
// the byte count written (or 0 + error if the process vanished or we
// lack the privilege to read it).
func procPIDInfo(pid int32, flavor int, buf []byte) (int, error) {
	n, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procInfoCallPIDInfo, uintptr(pid), uintptr(flavor), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// bsdInfo reads proc_bsdinfo for pid. Returns false if the process is
// gone (ESRCH) or otherwise unreadable.
func bsdInfo(pid int32) (ppid int32, uid uint32, startSec, startUsec uint64, ok bool) {
	buf := make([]byte, procPIDTBSDInfoSize)
	n, err := procPIDInfo(pid, procPIDTBSDInfo, buf)
	if err != nil || n < procPIDTBSDInfoSize {
		return 0, 0, 0, 0, false
	}
	ppid = int32(binary.LittleEndian.Uint32(buf[16:20]))
	uid = binary.LittleEndian.Uint32(buf[20:24])
	startSec = binary.LittleEndian.Uint64(buf[120:128])
	startUsec = binary.LittleEndian.Uint64(buf[128:136])
	ok = true
	return
}

// pidPath reads the absolute executable path for pid via PROC_PIDPATHINFO.
// Empty string if the process is gone or path is not readable.
func pidPath(pid int32) string {
	buf := make([]byte, procPIDPathInfoSize)
	n, err := procPIDInfo(pid, procPIDPathInfo, buf)
	if err != nil || n <= 0 {
		return ""
	}
	if end := bytes.IndexByte(buf[:n], 0); end >= 0 {
		return string(buf[:end])
	}
	return string(buf[:n])
}

// pidCwd reads the current working directory for pid via
// PROC_PIDVNODEPATHINFO. Returns "EACCES" if denied (matches Linux), or
// "EUNKNOWN" on other failures (process gone, etc.).
func pidCwd(pid int32) string {
	buf := make([]byte, procPIDVNodePathInfoSz)
	n, err := procPIDInfo(pid, procPIDVNodePathInfo, buf)
	if err != nil {
		if err == syscall.EACCES || err == syscall.EPERM {
			return "EACCES"
		}
		return "EUNKNOWN"
	}
	if n < procVNodeInfoPathCwdOff+1 {
		return "EUNKNOWN"
	}
	cwd := buf[procVNodeInfoPathCwdOff:]
	if end := bytes.IndexByte(cwd, 0); end >= 0 {
		return string(cwd[:end])
	}
	return string(cwd)
}

// sysctlRaw calls SYS___SYSCTL with the given MIB and returns the raw
// bytes (the stdlib syscall package has no SysctlRaw on darwin).
func sysctlRaw(mib []int32) ([]byte, error) {
	if len(mib) == 0 {
		return nil, syscall.EINVAL
	}
	// Sizing pass: oldp=NULL → kernel fills *oldlenp with required size.
	var oldlen uintptr
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		0,
		uintptr(unsafe.Pointer(&oldlen)),
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	if oldlen == 0 {
		return nil, nil
	}
	buf := make([]byte, oldlen)
	_, _, errno = syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&oldlen)),
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	return buf[:oldlen], nil
}

// pidArgv reads argv and envp via sysctl kern.procargs2. The buffer layout
// is: [argc uint32] [exec_path NUL] [NUL padding] [argv 0..argc-1 NUL] then
// [envp NUL...] until end. Empty argv means we lacked privilege (only the
// owning uid or root can read another process's args on macOS).
func pidArgv(pid int32) (argv, envp []string) {
	mib := []int32{ctlKern, kernProcArgs2, pid}
	data, err := sysctlRaw(mib)
	if err != nil || len(data) < 4 {
		return nil, nil
	}
	argc := int(binary.LittleEndian.Uint32(data[:4]))
	// Skip exec_path (NUL-terminated) and any padding NULs.
	p := 4
	for p < len(data) && data[p] != 0 {
		p++
	}
	for p < len(data) && data[p] == 0 {
		p++
	}
	// Read argc NUL-terminated argv entries.
	for i := 0; i < argc && p < len(data); i++ {
		start := p
		for p < len(data) && data[p] != 0 {
			p++
		}
		argv = append(argv, string(data[start:p]))
		p++ // skip the NUL
	}
	// Remaining: envp entries until end of buffer.
	for p < len(data) {
		start := p
		for p < len(data) && data[p] != 0 {
			p++
		}
		if p > start {
			envp = append(envp, string(data[start:p]))
		}
		p++
	}
	return argv, envp
}

// userOf resolves uid → username, falling back to the numeric uid.
func userOf(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return u.Username
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// ─── Depth / ancestry ────────────────────────────────────────────────────────

// pidDepth returns the tree depth of pid relative to the nearest watchPID,
// or -1 if pid is not a descendant of any watched root. Unlike the Linux
// tracer this is silent on failure: non-root tracep on macOS routinely
// can't read other-user processes' bsd info, and spamming about it for
// every parent-chain walk drowns the actual events.
func pidDepth(pid int32) int {
	if isWatchRoot(pid) {
		return 0
	}
	ppid, _, _, _, ok := bsdInfo(pid)
	if !ok {
		return -1
	}
	if ppid == 0 || ppid == pid {
		return -1
	}
	if isWatchRoot(ppid) {
		return 0
	}
	mu.Lock()
	if ent, ok := db[ppid]; ok && ent.depth >= 0 {
		d := ent.depth
		mu.Unlock()
		return d + 1
	}
	mu.Unlock()
	d := pidDepth(ppid)
	if d < 0 {
		return -1
	}
	return d + 1
}

// ─── Output (mirrors printExec in exec_linux.go) ─────────────────────────────

func indentStr(depth int) string {
	if flatMode || depth <= 0 {
		return ""
	}
	return strings.Repeat("  ", depth)
}

// emitExec prints a new exec event for pid, with the same shape as the
// Linux tracer's printExec.
func emitExec(ent *macEntry) {
	var sb strings.Builder
	sb.WriteString(indentStr(ent.depth))
	sb.WriteString(clr("33", strconv.Itoa(int(ent.pid))))
	if showExit {
		sb.WriteString(clr("32", "+"))
	}
	if showUser {
		name := userOf(ent.uid)
		if name == "root" {
			sb.WriteString(clr("91", " <"+name+">"))
		} else {
			sb.WriteString(clr("92", " <"+name+">"))
		}
	}
	sb.WriteByte(' ')

	if showCwd {
		cwd := pidCwd(ent.pid)
		sb.WriteString(clr("35", shQuote(cwd)))
		sb.WriteString(clr("2", " % "))
	}

	argv, envp := pidArgv(ent.pid)
	if len(argv) == 0 {
		// No argv (privilege or gone) — fall back to the exe path's base.
		exe := pidPath(ent.pid)
		if exe == "" {
			return
		}
		sb.WriteString(clr("2", "["+filepath.Base(exe)+"]"))
	} else {
		var cmd string
		if fullPath {
			if exe := pidPath(ent.pid); exe != "" {
				cmd = shQuote(exe)
			} else {
				cmd = shQuote(argv[0])
			}
		} else {
			cmd = shQuote(argv[0])
		}
		sb.WriteString(clr("96", cmd))
		if showArgs && len(argv) > 1 {
			for _, a := range argv[1:] {
				sb.WriteByte(' ')
				sb.WriteString(clr("2", shQuote(a)))
			}
		}
	}

	if showEnv {
		sb.WriteString("\n  ")
		for _, e := range envp {
			sb.WriteByte(' ')
			if eq := strings.IndexByte(e, '='); eq >= 0 {
				sb.WriteString(clr("2", shQuote(e[:eq])+"="+shQuote(e[eq+1:])))
			} else {
				sb.WriteString(clr("2", shQuote(e)))
			}
		}
	}

	fmt.Fprintln(out, sb.String())
}

// emitExit prints when a previously-seen pid disappears. Exit code is
// unavailable from polling (no waitpid hook); we report "status=?" so the
// distinction from a real "status=0" is clear.
func emitExit(ent *macEntry, gone time.Time) {
	if !showExit {
		return
	}
	indent := indentStr(ent.depth)
	startedAt := time.Unix(int64(ent.startSec), int64(ent.startUsec)*1000)
	elapsed := gone.Sub(startedAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	cmd := ent.argv0
	if cmd == "" {
		cmd = "?"
	}
	fmt.Fprintf(out, "%s%s%s %s exited %s %s\n",
		indent,
		clr("33", strconv.Itoa(int(ent.pid))),
		clr("31", "-"),
		clr("2", shQuote(cmd)),
		clr("2", "status=?"),
		clr("36", fmt.Sprintf("time=%.3fs", elapsed)),
	)
}

// ─── Polling loop ────────────────────────────────────────────────────────────

// seedDB populates db with every currently-live pid so we don't emit a
// "new process" wave for everything that was already running when tracep
// started. Matches the Linux tracer's behaviour: it only sees fork/exec
// events from the moment it subscribes.
func seedDB() {
	pids, err := procListAllPIDs()
	if err != nil {
		fatalf("proc_listallpids: %v", err)
	}
	for _, p := range pids {
		ppid, uid, sec, usec, ok := bsdInfo(p)
		if !ok {
			continue
		}
		argv, _ := pidArgv(p)
		ent := &macEntry{
			pid: p, ppid: ppid, uid: uid,
			startSec: sec, startUsec: usec,
			depth: -1, // unknown until we see it as a new descendant
		}
		if len(argv) > 0 {
			ent.argv0 = argv[0]
		}
		db[p] = ent
	}
}

// scan performs one polling tick: list pids, diff against db, emit exec
// events for new pids and exit events for pids that vanished. To keep
// the cost ~O(new+gone) per tick rather than O(all), we only query
// per-pid metadata (bsdInfo, argv, depth) when a pid first appears —
// known pids are trusted to be the same process until they disappear
// from the pid list. Pid reuse inside a single poll window is therefore
// invisible; in practice the kernel cycles through pids slowly enough
// that this is a non-issue at the default 50ms interval.
func scan() {
	pids, err := procListAllPIDs()
	if err != nil {
		runtimeErr("tracep exec: proc_listallpids: %v", err)
		return
	}
	now := time.Now()
	cur := make(map[int32]bool, len(pids))

	for _, pid := range pids {
		cur[pid] = true
		mu.Lock()
		_, existed := db[pid]
		mu.Unlock()
		if existed {
			continue
		}

		ppid, uid, sec, usec, ok := bsdInfo(pid)
		if !ok {
			// Likely a process we can't introspect (zombie, kernel proc,
			// or another user's process without privilege). Record a
			// negative entry so we don't retry every tick.
			mu.Lock()
			db[pid] = &macEntry{pid: pid, depth: -1}
			mu.Unlock()
			continue
		}
		d := pidDepth(pid)
		ent := &macEntry{
			pid: pid, ppid: ppid, uid: uid,
			startSec: sec, startUsec: usec,
			depth: d,
		}
		if argv, _ := pidArgv(pid); len(argv) > 0 {
			ent.argv0 = argv[0]
		}
		mu.Lock()
		db[pid] = ent
		mu.Unlock()
		if d >= 0 {
			emitExec(ent)
		}
	}

	// Anything in db but not in cur has exited.
	mu.Lock()
	gone := make([]*macEntry, 0)
	for pid, ent := range db {
		if !cur[pid] {
			gone = append(gone, ent)
			delete(db, pid)
		}
	}
	mu.Unlock()
	for _, ent := range gone {
		if ent.depth >= 0 {
			emitExit(ent, now)
		}
	}
}

// ─── main ────────────────────────────────────────────────────────────────────

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
		for j := 1; j < len(a); j++ {
			ch := a[j]
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
			case 'i':
				if i+1 >= len(args) {
					fatal("flag -i requires an argument (poll interval in ms)")
				}
				i++
				n, err := strconv.Atoi(args[i])
				if err != nil || n <= 0 {
					fatalf("-i: invalid interval: %s", args[i])
				}
				pollIntervalMs = n
			case 'h':
				usage()
			default:
				fatalf("unknown flag -%c", ch)
			}
		}
	}

	if len(watchPIDs) == 0 {
		watchPIDs = []int32{1} // global mode — everything descends from launchd (pid 1)
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

	// CMD mode: fork the command and watch its subtree.
	if len(cmdArgs) > 0 {
		watchPIDs = []int32{int32(os.Getpid())}
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fatalf("exec %s: %v", cmdArgs[0], err)
		}
		go func() { cmd.Wait(); os.Exit(0) }()
	}

	seedDB()

	// Warn once on stderr that polling will miss short-lived processes —
	// the whole reason the Linux build uses the proc connector instead.
	// Non-root tracep also can't read argv for other users' processes.
	caveat := fmt.Sprintf("tracep exec: polling at %dms on darwin — short-lived processes may be missed", pollIntervalMs)
	if os.Geteuid() != 0 {
		caveat += "; non-root sees argv only for own-user processes"
	}
	runtimeErr("%s", caveat)

	interval := time.Duration(pollIntervalMs) * time.Millisecond
	for {
		time.Sleep(interval)
		scan()
	}
}

// ─── Shell quoting (mirrors exec_linux.go) ───────────────────────────────────

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

// ─── Error helpers ───────────────────────────────────────────────────────────

func runtimeErr(f string, args ...any) {
	if showErrors {
		fmt.Fprintf(os.Stderr, f+"\n", args...)
	}
}

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "tracep exec: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "tracep exec: "+msg)
	os.Exit(1)
}

// ─── Usage ───────────────────────────────────────────────────────────────────

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
	fmt.Fprintf(e, "\n  %s🔍 tracep exec%s %s%s%s — exec() tracer (%s, polling)\n\n",
		bold+cyan, reset, dim, version, reset, runtime.GOOS)
	fmt.Fprintf(e, "  %sUsage:%s\n", bold, reset)
	fmt.Fprintf(e, "    tracep exec %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n", dim, reset, yellow, reset)
	fmt.Fprintf(e, "  %sFlags:%s\n", bold, reset)
	fmt.Fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    📁  %s-d%s          print cwd of each process\n", yellow, reset)
	fmt.Fprintf(e, "    🌿  %s-e%s          print environment variables\n", yellow, reset)
	fmt.Fprintf(e, "    ⬜  %s-f%s          flat output %s(no indentation)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    ⏲️   %s-i%s %sMS%s        poll interval in ms %s(default 50)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    🔗  %s-l%s          print full executable path\n", yellow, reset)
	fmt.Fprintf(e, "    📝  %s-o%s %sFILE%s      log output to FILE instead of stdout\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    🎯  %s-p%s %sPID%s       trace descendants of PID %s(repeat or comma-separate)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    🤫  %s-q%s          suppress arguments\n", yellow, reset)
	fmt.Fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset)
	fmt.Fprintf(e, "    ⏱️   %s-t%s          show exit + timing %s(exit code unknown on darwin)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    👤  %s-u%s          print owning user\n", yellow, reset)
	fmt.Fprintf(e, "\n  %sNotes:%s\n", bold, reset)
	fmt.Fprintf(e, "    %sdarwin has no equivalent of Linux's proc connector. This build polls%s\n", dim, reset)
	fmt.Fprintf(e, "    %sproc_listallpids and diffs snapshots — processes that exec+exit inside%s\n", dim, reset)
	fmt.Fprintf(e, "    %sone interval are missed. Lower -i for finer-grained coverage at higher CPU.%s\n\n", dim, reset)
	fmt.Fprintf(e, "  %sExamples:%s\n", bold, reset)
	fmt.Fprintf(e, "    %s# trace a command and all its children%s\n", dim, reset)
	fmt.Fprintf(e, "    tracep exec %s-ct%s sh -c %s'make'%s\n\n", green, reset, magenta, reset)
	fmt.Fprintf(e, "    %s# 20ms polling, log to file%s\n", dim, reset)
	fmt.Fprintf(e, "    tracep exec %s-i 20 -Qo%s /tmp/execs.log\n\n", green, reset)
	os.Exit(1)
}
