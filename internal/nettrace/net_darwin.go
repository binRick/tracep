//go:build darwin

// macOS network connection tracer — polls `lsof -nP -i` every -i ms
// (default 1000) and prints each newly-observed socket. The Linux
// backend is event-driven via netlink conntrack + /proc; macOS has no
// equivalent so we approximate by diffing snapshots. With -p PID,...
// lsof runs server-side filtered so the per-tick cost is small.
//
// What's the same as Linux: PID, command, protocol (TCP/UDP), src:port,
// dst:port, and the -c/-u/-o/-Q/-p flags. What's missing: kernel state
// labels (ESTAB/TIME_WAIT/etc.), update/close events (-U/-t), reverse
// DNS (-r), direction inference (-O), v4/v6 filtering. Sub-poll-interval
// micro-flows are missed — a polling tradeoff, not a defect.
package nettrace

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version is set at build time via -ldflags -X.
var version = "dev"

// ─── Globals ─────────────────────────────────────────────────────────────────

var (
	watchPIDs      []int32
	colorMode      bool
	colorForce     bool
	showUser       bool
	showErrors     = true
	out            io.Writer = os.Stdout
	pollIntervalMs           = 1000
)

// ─── Per-connection state ────────────────────────────────────────────────────

type macConnKey struct {
	pid           int
	proto         string
	src, dst      string
	sport, dport  int
}

type macConn struct {
	key  macConnKey
	comm string
	uid  uint32
}

var (
	mu   sync.Mutex
	seen = map[macConnKey]bool{}
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

func runtimeErr(f string, args ...any) {
	if showErrors {
		fmt.Fprintf(os.Stderr, f+"\n", args...)
	}
}

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "tracep net: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "tracep net: "+msg)
	os.Exit(1)
}

func userOf(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return u.Username
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// ─── lsof scan ───────────────────────────────────────────────────────────────

// lsofArgs builds the lsof command for this tick. -F pcLPnu emits one
// field per line with stable codes (p pid, c command, L login, u uid,
// P protocol, n name); -nP suppresses DNS/service lookups to keep output
// fast; -p limits to the watched PIDs when given. The 'u' field is what
// lets -u report the real owner — without it curUID stays 0 and every
// connection mislabels as <root>.
func lsofArgs() []string {
	a := []string{"-nP", "-i", "-F", "pcLPnu"}
	if len(watchPIDs) > 0 {
		ps := make([]string, 0, len(watchPIDs))
		for _, p := range watchPIDs {
			ps = append(ps, strconv.Itoa(int(p)))
		}
		// -a ANDs the -i (network) and -p (pid) selections. Without it lsof
		// ORs its selection options, so `-i -p PID` lists *every* host socket
		// (the -p is effectively ignored) and the per-PID filter is lost.
		a = append(a, "-a", "-p", strings.Join(ps, ","))
	}
	return a
}

// scanConns runs one lsof pass, parses the -F output, and emits a line
// for every connection it hasn't seen before. New entries are added to
// `seen`; departed entries are not currently surfaced (no close event
// support on the macOS backend yet).
func scanConns() {
	cmd := exec.Command("/usr/sbin/lsof", lsofArgs()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		runtimeErr("tracep net: lsof: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		runtimeErr("tracep net: lsof start: %v", err)
		return
	}

	var (
		curPID  int
		curComm string
		curUID  uint32
		curProto string
	)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 8192), 1<<20)
	newKeys := []macConn{}

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			if v, err := strconv.Atoi(line[1:]); err == nil {
				curPID = v
			}
			// New process record — reset per-process/fd state so a stale 'P'
			// or 'u' from a previous process can't leak into the next one.
			curProto = ""
			curUID = 0
		case 'c':
			curComm = line[1:]
		case 'L':
			// login user (string) — fallback when -u isn't requested
		case 'u':
			// per-process uid (numeric) — emitted with the right -F format
			if v, err := strconv.ParseUint(line[1:], 10, 32); err == nil {
				curUID = uint32(v)
			}
		case 'f':
			// New fd record within the current process — clear the protocol
			// so file-fd 'n' lines that follow without a 'P' line are skipped.
			curProto = ""
		case 'P':
			curProto = line[1:]
		case 'n':
			// "n*:54321", "n127.0.0.1:54321", "n[::]:5353", or
			// "n127.0.0.1:55310->1.2.3.4:443" for connected sockets.
			// When `-p PID` is set lsof also lists non-network fds (open
			// files, UNIX sockets); those start with '/' — skip them.
			body := line[1:]
			if body == "" || body[0] == '/' || curProto == "" {
				continue
			}
			src, dst, ok := splitConn(body)
			if !ok {
				continue
			}
			sip, sport := splitHostPort(src)
			dip, dport := splitHostPort(dst)
			if sport == 0 && dport == 0 {
				continue
			}
			k := macConnKey{
				pid: curPID, proto: curProto,
				src: sip, sport: sport,
				dst: dip, dport: dport,
			}
			mu.Lock()
			already := seen[k]
			if !already {
				seen[k] = true
			}
			mu.Unlock()
			if already {
				continue
			}
			newKeys = append(newKeys, macConn{key: k, comm: curComm, uid: curUID})
		}
	}
	_ = cmd.Wait()
	for _, c := range newKeys {
		emit(&c)
	}
}

// splitConn separates "src->dst" into the two halves. For a listening
// or unconnected socket there is no arrow, so dst is "".
func splitConn(s string) (src, dst string, ok bool) {
	if i := strings.Index(s, "->"); i >= 0 {
		return s[:i], s[i+2:], true
	}
	return s, "", true
}

// splitHostPort handles "*:53", "127.0.0.1:53", "[::]:5353", "[::1]:53",
// or "*:*". Returns ip="" and port=0 for the wildcards.
func splitHostPort(s string) (ip string, port int) {
	if s == "" || s == "*:*" {
		return "", 0
	}
	// Bracketed IPv6: "[ip]:port".
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return "", 0
		}
		ip = s[1:end]
		port, _ = strconv.Atoi(s[end+2:])
		return
	}
	colon := strings.LastIndex(s, ":")
	if colon < 0 {
		return s, 0
	}
	ip = s[:colon]
	if ip == "*" {
		ip = ""
	}
	if s[colon+1:] != "*" {
		port, _ = strconv.Atoi(s[colon+1:])
	}
	return
}

// ─── Output ──────────────────────────────────────────────────────────────────

// emit prints one connection in roughly the Linux format. dst empty
// means it's a bound/listening socket; we print "*:0" to keep columns.
func emit(c *macConn) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%7d ", c.key.pid)
	comm := c.comm
	if comm == "" {
		comm = "?"
	}
	if len(comm) > 12 {
		comm = comm[:11] + "…"
	}
	sb.WriteString(clr("96", fmt.Sprintf("%-12s", comm)))
	if showUser {
		u := userOf(c.uid)
		if u == "root" {
			sb.WriteString(clr("91", " <"+u+">"))
		} else {
			sb.WriteString(clr("92", " <"+u+">"))
		}
	}
	sb.WriteByte(' ')
	sb.WriteString(clr("2", fmt.Sprintf("%-4s", c.key.proto)))
	sb.WriteByte(' ')
	src := joinHostPort(c.key.src, c.key.sport)
	sb.WriteString(clr("32", fmt.Sprintf("%-30s", src)))
	sb.WriteByte(' ')
	if c.key.dst == "" && c.key.dport == 0 {
		sb.WriteString(clr("2", "•")) // unconnected/listening
	} else {
		sb.WriteString(clr("36", "→"))
	}
	sb.WriteByte(' ')
	dst := joinHostPort(c.key.dst, c.key.dport)
	sb.WriteString(clr("33", fmt.Sprintf("%-30s", dst)))
	fmt.Fprintln(out, sb.String())
}

// joinHostPort renders an ip:port pair, bracketing IPv6 ("[fe80::1]:443")
// so the colon between literal and port isn't visually ambiguous.
// Wildcards print as "*:0" for layout consistency.
func joinHostPort(ip string, port int) string {
	if ip == "" {
		return fmt.Sprintf("*:%d", port)
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// ─── Main ────────────────────────────────────────────────────────────────────

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
			case 'u':
				showUser = true
			case 'Q':
				showErrors = false
			case 't', 'U', 'r', '4', '6', 'O':
				// recognized for Linux compatibility but no-op on macOS;
				// silently ignore so the same command lines work.
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

	// CMD mode: fork the command and watch its subtree by adding the
	// child's pid (and any pid spawned beneath it that lsof catches)
	// to the watch set. We keep it simple — just the direct child.
	if len(cmdArgs) > 0 {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fatalf("exec %s: %v", cmdArgs[0], err)
		}
		watchPIDs = append(watchPIDs, int32(cmd.Process.Pid))
		go func() { cmd.Wait(); os.Exit(0) }()
	}

	// Seed: scan once and mark everything currently open as already seen,
	// so we only emit connections that appear after tracep starts. Use
	// the same fd-aware parsing as scanConns so non-network fds don't
	// contaminate the seed set.
	cmd := exec.Command("/usr/sbin/lsof", lsofArgs()...)
	if data, err := cmd.Output(); err == nil {
		var pid int
		var proto string
		for _, line := range strings.Split(string(data), "\n") {
			if len(line) < 2 {
				continue
			}
			switch line[0] {
			case 'p':
				pid, _ = strconv.Atoi(line[1:])
				proto = ""
			case 'f':
				proto = ""
			case 'P':
				proto = line[1:]
			case 'n':
				body := line[1:]
				if body == "" || body[0] == '/' || proto == "" {
					continue
				}
				src, dst, _ := splitConn(body)
				sip, sport := splitHostPort(src)
				dip, dport := splitHostPort(dst)
				seen[macConnKey{
					pid: pid, proto: proto,
					src: sip, sport: sport,
					dst: dip, dport: dport,
				}] = true
			}
		}
	}

	caveat := fmt.Sprintf("tracep net: polling at %dms on darwin — short-lived connections may be missed", pollIntervalMs)
	if os.Geteuid() != 0 {
		caveat += "; non-root sees sockets only for own-user processes"
	}
	runtimeErr("%s", caveat)

	interval := time.Duration(pollIntervalMs) * time.Millisecond
	for {
		time.Sleep(interval)
		scanConns()
	}
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
	fmt.Fprintf(e, "\n  %s🌐 tracep net%s %s%s%s — network-connection tracer (%s, polling)\n\n",
		bold+cyan, reset, dim, version, reset, runtime.GOOS)
	fmt.Fprintf(e, "  %sUsage:%s\n", bold, reset)
	fmt.Fprintf(e, "    tracep net %s[flags]%s %s[-p PID[,PID,...] | CMD...]%s\n\n", dim, reset, yellow, reset)
	fmt.Fprintf(e, "  %sFlags:%s\n", bold, reset)
	fmt.Fprintf(e, "    🎨  %s-c%s          colorize output\n", yellow, reset)
	fmt.Fprintf(e, "    ⏲️   %s-i%s %sMS%s        poll interval in ms %s(default 1000)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    📝  %s-o%s %sFILE%s      log output to FILE\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    🎯  %s-p%s %sPID%s       watch only PID's own connections\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    👤  %s-u%s          print owning user\n", yellow, reset)
	fmt.Fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset)
	fmt.Fprintf(e, "    %s-t/-U/-r/-4/-6/-O%s recognized for Linux compatibility (no-op on darwin)\n", dim, reset)
	fmt.Fprintf(e, "\n  %sNotes:%s\n", bold, reset)
	fmt.Fprintf(e, "    %sdarwin has no netlink conntrack. This build polls `lsof -nP -i` and%s\n", dim, reset)
	fmt.Fprintf(e, "    %sdiffs snapshots, so short-lived connections may not be observed. Lower%s\n", dim, reset)
	fmt.Fprintf(e, "    %s-i for finer coverage at higher CPU; use -p to scope lsof server-side.%s\n\n", dim, reset)
	fmt.Fprintf(e, "  %sExamples:%s\n", bold, reset)
	fmt.Fprintf(e, "    %s# watch one process's connections%s\n", dim, reset)
	fmt.Fprintf(e, "    tracep net %s-c -p%s 1234\n\n", green, reset)
	fmt.Fprintf(e, "    %s# trace a command's subtree%s\n", dim, reset)
	fmt.Fprintf(e, "    tracep net %s-cu%s curl %shttps://example.com%s\n\n", green, reset, magenta, reset)
	os.Exit(1)
}
