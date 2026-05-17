// proc-trace-dns — watch DNS queries made by every process on a Linux system.
//
// It opens a raw AF_PACKET socket, captures UDP port-53 traffic system-wide,
// parses the DNS wire format, and attributes each query to the process that
// made it via /proc/net/udp socket→inode→PID resolution.
//
// Requires: root or CAP_NET_RAW.  Linux only.  No external dependencies.
package dnstrace

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var version = "dev"

// ── CLI flags ────────────────────────────────────────────────────────────────

// Flag pointers stay package-scoped because dns.go/proc.go/packet.go
// dereference them, but they are bound to a private FlagSet inside Main()
// so they never collide with another subcommand's global flags.
var (
	fColor  *bool
	fDomain *string
	fFlat   *bool
	fJSON   *bool
	fNames  *string
	fOutput *string
	fPIDs   *string
	fQuiet  *bool
	fQQuiet *bool
	fTime   *bool
	fTypes  *string
)

// ── Runtime state ────────────────────────────────────────────────────────────

var (
	useColor  bool
	out       = os.Stdout
	nameSet   map[string]bool
	pidSet    map[int]bool
	typeSet   map[string]bool
)

// ── Main ─────────────────────────────────────────────────────────────────────

func Main() {
	fs := flag.NewFlagSet("tracep dns", flag.ExitOnError)
	fColor = fs.Bool("c", false, "force ANSI color output")
	fDomain = fs.String("d", "", "only show queries matching this domain substring")
	fFlat = fs.Bool("f", false, "flat output — no column alignment")
	fJSON = fs.Bool("j", false, "JSON output (one object per line)")
	fNames = fs.String("n", "", "only show queries from these process names (comma-separated)")
	fOutput = fs.String("o", "", "append output to FILE instead of stdout")
	fPIDs = fs.String("p", "", "only show queries from these PIDs (comma-separated)")
	fQuiet = fs.Bool("q", false, "quiet — print only queried hostnames, one per line")
	fQQuiet = fs.Bool("Q", false, "suppress error messages")
	fTime = fs.Bool("t", false, "show timestamp (RFC3339) for each query")
	fTypes = fs.String("T", "", "only show these DNS record types, e.g. A,AAAA,MX (comma-separated)")

	fs.Usage = func() {
		// Detect color: respect NO_COLOR, fall back to -c flag or isatty on stderr.
		color := *fColor || (isatty(2) && os.Getenv("NO_COLOR") == "")
		h := func(plain, colored string) string {
			if color {
				return colored
			}
			return plain
		}

		bold   := h("", "\033[1m")
		cyan   := h("", "\033[36m")
		yellow := h("", "\033[33m")
		green  := h("", "\033[32m")
		dim    := h("", "\033[2m")
		reset  := h("", "\033[0m")

		e := func(emoji string) string {
			if color {
				return emoji + " "
			}
			return ""
		}

		fmt.Fprintf(os.Stderr, "\n%s%sproc-trace-dns%s  %s(v%s)%s\n", bold, cyan, reset, dim, version, reset)
		fmt.Fprintf(os.Stderr, "%sWatch every DNS query your processes make, in real time.%s\n\n", dim, reset)

		fmt.Fprintf(os.Stderr, "%s%sUSAGE%s\n", bold, yellow, reset)
		fmt.Fprintf(os.Stderr, "  proc-trace-dns [flags] [-- CMD [args...]]\n\n")

		fmt.Fprintf(os.Stderr, "%s%s%sFLAGS%s\n", e("🚩"), bold, yellow, reset)

		fmt.Fprintf(os.Stderr, "  %s%s-c%s              %sforce ANSI color output%s\n",         bold, cyan, reset, dim, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-t%s              %sshow timestamp (RFC3339) for each query%s\n", bold, cyan, reset, dim, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-q%s              %squiet — print only queried hostnames, one per line%s\n", bold, cyan, reset, dim, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-Q%s              %ssuppress error messages%s\n",          bold, cyan, reset, dim, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-f%s              %sflat output — no column alignment%s\n", bold, cyan, reset, dim, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-j%s              %sJSON output (one object per line)%s\n", bold, cyan, reset, dim, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-n%s %sNAME,...%s      only show queries from these process names\n", bold, cyan, reset, yellow, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-p%s %sPID,...%s       only show queries from these PIDs\n",          bold, cyan, reset, yellow, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-d%s %sDOMAIN%s        only show queries matching this domain substring\n", bold, cyan, reset, yellow, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-T%s %sTYPE,...%s      only show these DNS record types (e.g. A,AAAA,MX)\n", bold, cyan, reset, yellow, reset)
		fmt.Fprintf(os.Stderr, "  %s%s-o%s %sFILE%s          append output to FILE instead of stdout\n\n",  bold, cyan, reset, yellow, reset)

		fmt.Fprintf(os.Stderr, "%s%s%sEXAMPLES%s\n", e("💡"), bold, yellow, reset)
		ex := func(cmd, comment string) {
			fmt.Fprintf(os.Stderr, "  %s%s%-52s%s%s# %s%s\n", bold, green, cmd, reset, dim, comment, reset)
		}
		ex("sudo proc-trace-dns",                                  "system-wide, all processes")
		ex("sudo proc-trace-dns -n curl,wget",                     "filter by process name")
		ex("sudo proc-trace-dns -p 1234,5678",                     "filter by PID")
		ex("sudo proc-trace-dns -d amazonaws.com",                 "filter by domain substring")
		ex("sudo proc-trace-dns -T A,AAAA",                        "only show A and AAAA records")
		ex("sudo proc-trace-dns -t -n firefox",                    "timestamped Firefox queries")
		ex("sudo proc-trace-dns -j | jq .",                        "JSON output, pretty-printed")
		ex("sudo proc-trace-dns -- curl https://example.com",      "trace a single command")
		fmt.Fprintf(os.Stderr, "\n%s%sRequires root or CAP_NET_RAW. Linux only.%s\n\n", e("⚠️ "), dim, reset)
	}
	fs.Parse(os.Args[1:])

	nameSet = splitSet(*fNames)
	typeSet = splitSetUpper(*fTypes)
	pidSet = parsePIDs(*fPIDs)

	useColor = *fColor || (isatty(1) && os.Getenv("NO_COLOR") == "")

	if *fOutput != "" {
		f, err := os.OpenFile(*fOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			die("open output file: %v", err)
		}
		defer f.Close()
		out = f
		if !*fColor {
			useColor = false
		}
	}

	// Raw AF_PACKET socket — captures all frames on all interfaces.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		die("socket: %v\nHint: run as root or: sudo setcap cap_net_raw+eip proc-trace-dns", err)
	}
	defer syscall.Close(fd)

	proc := newProcCache()

	// in-flight DNS queries, keyed by transaction ID
	pending := make(map[uint16]*dnsEvent)

	// If a command was given after --, run it and filter to its PID.
	if fs.NArg() > 0 {
		cmd := exec.Command(fs.Arg(0), fs.Args()[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			die("start command: %v", err)
		}
		pidSet[cmd.Process.Pid] = true
		go func() {
			cmd.Wait()
			time.Sleep(500 * time.Millisecond) // drain final responses
			os.Exit(0)
		}()
	}

	// Graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigs; os.Exit(0) }()

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if !*fQQuiet {
				logErr("recvfrom: %v", err)
			}
			continue
		}

		msg, srcPort, dstPort, ok := parseDNSFromPacket(buf[:n])
		if !ok {
			continue
		}

		now := time.Now()
		isQuery := msg.flags&0x8000 == 0 // QR bit

		switch {
		case isQuery && dstPort == 53:
			// Outgoing query — attribute to a process.
			pid, pname := proc.lookup(srcPort)
			pending[msg.id] = &dnsEvent{
				txID:    msg.id,
				query:   msg.question,
				qtype:   qtypeStr(msg.qtype),
				pid:     pid,
				pname:   pname,
				srcPort: srcPort,
				sent:    now,
			}

		case !isQuery && srcPort == 53:
			// Incoming response — match to the pending query.
			ev, found := pending[msg.id]
			if !found {
				continue
			}
			delete(pending, msg.id)
			ev.answers = msg.answers
			ev.rcode = rcodeStr(msg.flags & 0x000F)
			ev.latency = now.Sub(ev.sent)
			ev.ts = now
			emit(ev)
		}
	}
}

// ── Output ───────────────────────────────────────────────────────────────────

type dnsEvent struct {
	txID    uint16
	query   string
	qtype   string
	pid     int
	pname   string
	srcPort uint16
	sent    time.Time
	answers []string
	rcode   string
	latency time.Duration
	ts      time.Time
}

func emit(ev *dnsEvent) {
	if len(nameSet) > 0 && !nameSet[ev.pname] {
		return
	}
	if len(pidSet) > 0 && !pidSet[ev.pid] {
		return
	}
	if len(typeSet) > 0 && !typeSet[ev.qtype] {
		return
	}
	if *fDomain != "" && !strings.Contains(ev.query, *fDomain) {
		return
	}

	switch {
	case *fQuiet:
		fmt.Fprintln(out, ev.query)
	case *fJSON:
		emitJSON(ev)
	default:
		emitText(ev)
	}
}

func emitJSON(ev *dnsEvent) {
	m := map[string]interface{}{
		"pid":        ev.pid,
		"name":       ev.pname,
		"type":       ev.qtype,
		"query":      ev.query,
		"answers":    ev.answers,
		"rcode":      ev.rcode,
		"latency_ms": float64(ev.latency.Microseconds()) / 1000.0,
	}
	if *fTime {
		m["ts"] = ev.ts.Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(m)
	fmt.Fprintln(out, string(b))
}

// ANSI color codes
const (
	colReset = "\033[0m"
	colPID   = "\033[33m"  // amber  — PID
	colName  = "\033[96m"  // cyan   — process name
	colType  = "\033[35m"  // violet — record type
	colHost  = "\033[32m"  // green  — queried hostname
	colIP    = "\033[34m"  // blue   — resolved addresses
	colErr   = "\033[31m"  // red    — NXDOMAIN / errors
	colDim   = "\033[90m"  // grey   — latency, arrows
	colTS    = "\033[36m"  // cyan   — timestamp
)

func c(code, s string) string {
	if !useColor || s == "" {
		return s
	}
	return code + s + colReset
}

func emitText(ev *dnsEvent) {
	var b strings.Builder

	if *fTime {
		b.WriteString(c(colTS, ev.ts.Format("15:04:05")))
		b.WriteString("  ")
	}

	if *fFlat {
		fmt.Fprintf(&b, "%s  %s  %s  %s  ",
			c(colPID, strconv.Itoa(ev.pid)),
			c(colName, ev.pname),
			c(colType, ev.qtype),
			c(colHost, ev.query),
		)
	} else {
		fmt.Fprintf(&b, "%-7s  %-15s  %-5s  %-42s  ",
			c(colPID, strconv.Itoa(ev.pid)),
			c(colName, trunc(ev.pname, 15)),
			c(colType, ev.qtype),
			c(colHost, ev.query),
		)
	}

	b.WriteString(c(colDim, "→ "))

	if ev.rcode == "NOERROR" || ev.rcode == "" {
		if len(ev.answers) > 0 {
			b.WriteString(c(colIP, strings.Join(ev.answers, " ")))
		}
	} else {
		b.WriteString(c(colErr, ev.rcode))
	}

	b.WriteString("  ")
	b.WriteString(c(colDim, fmtLatency(ev.latency)))

	fmt.Fprintln(out, b.String())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func fmtLatency(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func splitSet(s string) map[string]bool {
	m := make(map[string]bool)
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

func splitSetUpper(s string) map[string]bool {
	m := make(map[string]bool)
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(strings.ToUpper(p)); p != "" {
			m[p] = true
		}
	}
	return m
}

func parsePIDs(s string) map[int]bool {
	m := make(map[int]bool)
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			m[n] = true
		}
	}
	return m
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "proc-trace-dns: "+format+"\n", args...)
	os.Exit(1)
}

func logErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

// isatty returns true when fd refers to a terminal.
func isatty(fd int) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
