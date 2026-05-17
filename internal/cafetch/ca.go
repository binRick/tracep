package cafetch

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const version = "v1.0.0"

func Main() {
	var (
		port       = flag.Int("port", 443, "TLS port to connect to")
		output     = flag.String("o", "", "Output file (default: <hostname>-ca.pem, use - for stdout)")
		fetchRoot  = flag.Bool("fetch-root", false, "Fetch root CA via AIA URL")
		insecure   = flag.Bool("insecure", false, "Skip TLS certificate verification")
		all        = flag.Bool("all", false, "Save full chain including leaf certificate")
		timeout    = flag.Int("timeout", 10, "Connection timeout in seconds")
		showVer    = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("tls-ca-fetch", version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tls-ca-fetch [flags] <hostname> [port]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	hostname := args[0]

	// Allow port as positional arg after hostname
	if len(args) >= 2 {
		p, err := strconv.Atoi(args[1])
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[1])
			os.Exit(1)
		}
		*port = p
	}

	addr := fmt.Sprintf("%s:%d", hostname, *port)
	fmt.Printf("→ Connecting to %s …\n\n", addr)

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: *insecure,
			ServerName:         hostname,
		},
	}

	ctx := &timeoutContext{deadline: time.Now().Add(time.Duration(*timeout) * time.Second)}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		fmt.Fprintln(os.Stderr, "error: server sent no certificates")
		os.Exit(1)
	}

	fmt.Printf("Chain received: %d certificate(s)\n", len(certs))
	fmt.Println(strings.Repeat("─", 70))

	for i, cert := range certs {
		role := certRole(cert, i, len(certs))
		fmt.Printf("  [%d] %-16s CN=%-40s IsCA=%v\n", i, role, shortCN(cert.Subject.CommonName), cert.IsCA)
		fmt.Printf("       Issuer : %s\n", shortCN(cert.Issuer.CommonName))
		fmt.Printf("       Expires: %s\n", cert.NotAfter.Format("2006-01-02"))
		if len(cert.IssuingCertificateURL) > 0 {
			fmt.Printf("       AIA    : %s\n", cert.IssuingCertificateURL[0])
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("─", 70))

	// Collect CA certs to save
	var toSave []*x509.Certificate
	for i, cert := range certs {
		if *all || i > 0 || cert.IsCA {
			toSave = append(toSave, cert)
		}
	}

	// Optionally fetch root via AIA
	if *fetchRoot {
		top := certs[len(certs)-1]
		if len(top.IssuingCertificateURL) > 0 {
			aiaURL := top.IssuingCertificateURL[0]
			fmt.Printf("\nFetching root CA via AIA: %s\n", aiaURL)
			root, err := fetchDERCert(aiaURL, *timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: AIA fetch failed: %v\n", err)
			} else {
				fmt.Printf("  Root: CN=%s  Expires: %s\n", shortCN(root.Subject.CommonName), root.NotAfter.Format("2006-01-02"))
				toSave = append(toSave, root)
			}
		} else {
			fmt.Fprintln(os.Stderr, "warning: no AIA URL found in topmost certificate")
		}
	}

	if len(toSave) == 0 {
		fmt.Fprintln(os.Stderr, "\nwarning: no CA certificates found in chain")
		if len(certs) > 0 && len(certs[0].IssuingCertificateURL) > 0 {
			fmt.Fprintf(os.Stderr, "  Try -fetch-root. AIA URL: %s\n", certs[0].IssuingCertificateURL[0])
		}
		os.Exit(1)
	}

	// Determine output destination
	outPath := *output
	if outPath == "" {
		outPath = hostname + "-ca.pem"
	}

	var w io.Writer
	if outPath == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	pemCount := 0
	for _, cert := range toSave {
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			fmt.Fprintf(os.Stderr, "error writing PEM: %v\n", err)
			os.Exit(1)
		}
		pemCount++
	}

	if outPath != "-" {
		fmt.Printf("\n✓ Saved %d CA certificate(s) → %s\n", pemCount, outPath)
		fmt.Printf("  Verified: %d PEM block(s) readable in output file\n", pemCount)
	}
}

func certRole(cert *x509.Certificate, idx, total int) string {
	if idx == 0 && !cert.IsCA {
		return "leaf"
	}
	if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
		return "root CA"
	}
	if cert.IsCA {
		return "intermediate CA"
	}
	return "unknown"
}

func shortCN(cn string) string {
	if len(cn) > 38 {
		return cn[:35] + "..."
	}
	return cn
}

func fetchDERCert(url string, timeoutSec int) (*x509.Certificate, error) {
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try DER first
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Try PEM
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	return nil, fmt.Errorf("could not parse certificate from %s", url)
}

// timeoutContext is a minimal context.Context that only implements the deadline.
type timeoutContext struct {
	deadline time.Time
}

func (c *timeoutContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *timeoutContext) Done() <-chan struct{}         { return nil }
func (c *timeoutContext) Err() error                   { return nil }
func (c *timeoutContext) Value(key any) any            { return nil }
