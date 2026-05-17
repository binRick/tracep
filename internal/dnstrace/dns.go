package dnstrace

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// dnsMsg holds the parsed fields from a DNS wire-format message that we care about.
type dnsMsg struct {
	id       uint16
	flags    uint16   // raw flags word; QR=bit15, RCODE=bits3-0
	question string   // queried name
	qtype    uint16   // question type
	answers  []string // human-readable answer values
}

// parseDNS parses a DNS wire-format message.
// It is intentionally minimal — only the fields needed for display are decoded.
func parseDNS(data []byte) (*dnsMsg, bool) {
	if len(data) < 12 {
		return nil, false
	}
	msg := &dnsMsg{
		id:    binary.BigEndian.Uint16(data[0:2]),
		flags: binary.BigEndian.Uint16(data[2:4]),
	}
	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	ancount := int(binary.BigEndian.Uint16(data[6:8]))

	off := 12

	// Questions
	for i := 0; i < qdcount; i++ {
		name, n, ok := readName(data, off)
		if !ok {
			return nil, false
		}
		off = n
		if off+4 > len(data) {
			return nil, false
		}
		qt := binary.BigEndian.Uint16(data[off : off+2])
		off += 4 // QTYPE + QCLASS
		if i == 0 {
			msg.question = name
			msg.qtype = qt
		}
	}

	// Answers
	for i := 0; i < ancount; i++ {
		_, n, ok := readName(data, off)
		if !ok {
			break
		}
		off = n
		if off+10 > len(data) {
			break
		}
		rtype := binary.BigEndian.Uint16(data[off : off+2])
		off += 8 // TYPE(2) + CLASS(2) + TTL(4)
		rdlen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+rdlen > len(data) {
			break
		}
		rdata := data[off : off+rdlen]
		rdataOff := off - rdlen
		off += rdlen

		switch rtype {
		case 1: // A
			if len(rdata) == 4 {
				msg.answers = append(msg.answers, net.IP(rdata).String())
			}
		case 28: // AAAA
			if len(rdata) == 16 {
				msg.answers = append(msg.answers, net.IP(rdata).String())
			}
		case 5: // CNAME
			if cname, _, ok := readName(data, rdataOff); ok {
				msg.answers = append(msg.answers, "CNAME:"+cname)
			}
		case 15: // MX — skip 2-byte preference
			if rdlen > 2 {
				if mx, _, ok := readName(data, rdataOff+2); ok {
					msg.answers = append(msg.answers, "MX:"+mx)
				}
			}
		case 16: // TXT
			for _, s := range parseTXT(rdata) {
				msg.answers = append(msg.answers, s)
			}
		case 33: // SRV — skip 6-byte priority/weight/port
			if rdlen > 6 {
				if srv, _, ok := readName(data, rdataOff+6); ok {
					msg.answers = append(msg.answers, "SRV:"+srv)
				}
			}
		case 12: // PTR
			if ptr, _, ok := readName(data, rdataOff); ok {
				msg.answers = append(msg.answers, ptr)
			}
		case 2: // NS
			if ns, _, ok := readName(data, rdataOff); ok {
				msg.answers = append(msg.answers, "NS:"+ns)
			}
		}
	}

	return msg, true
}

// readName reads a DNS compressed name starting at offset in data.
// It follows compression pointers and returns the decoded name and the
// offset immediately after the name field (ignoring pointer destinations).
func readName(data []byte, off int) (string, int, bool) {
	var labels []string
	origOff := -1

	for {
		if off >= len(data) {
			return "", 0, false
		}
		l := int(data[off])

		switch {
		case l == 0:
			off++
			if origOff != -1 {
				off = origOff
			}
			return strings.Join(labels, "."), off, true

		case l&0xC0 == 0xC0: // compression pointer
			if off+2 > len(data) {
				return "", 0, false
			}
			if origOff == -1 {
				origOff = off + 2
			}
			off = int(binary.BigEndian.Uint16(data[off:off+2]) & 0x3FFF)

		case l&0xC0 == 0: // normal label
			off++
			if off+l > len(data) {
				return "", 0, false
			}
			labels = append(labels, string(data[off:off+l]))
			off += l

		default:
			return "", 0, false // reserved bits
		}
	}
}

// parseTXT decodes a TXT RDATA into individual strings.
func parseTXT(data []byte) []string {
	var out []string
	for len(data) > 0 {
		l := int(data[0])
		data = data[1:]
		if l > len(data) {
			break
		}
		out = append(out, string(data[:l]))
		data = data[l:]
	}
	return out
}

// qtypeStr returns the string name for a DNS QTYPE.
func qtypeStr(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// rcodeStr returns the string name for a DNS RCODE (lower 4 bits).
func rcodeStr(rcode uint16) string {
	switch rcode & 0xF {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode&0xF)
	}
}
