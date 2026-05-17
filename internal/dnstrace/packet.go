package dnstrace

import "encoding/binary"

// parseDNSFromPacket extracts a DNS message from a raw Ethernet frame captured
// via AF_PACKET. It handles IPv4 and IPv6, UDP only (TCP DNS not supported).
// Returns the DNS message, source port, destination port, and whether parsing
// succeeded.
func parseDNSFromPacket(pkt []byte) (*dnsMsg, uint16, uint16, bool) {
	if len(pkt) < 14 {
		return nil, 0, 0, false
	}
	ethertype := binary.BigEndian.Uint16(pkt[12:14])

	switch ethertype {
	case 0x0800: // IPv4
		return parseDNSv4(pkt[14:])
	case 0x86DD: // IPv6
		return parseDNSv6(pkt[14:])
	default:
		return nil, 0, 0, false
	}
}

// parseDNSv4 handles an IPv4 payload (after the Ethernet header).
func parseDNSv4(ip []byte) (*dnsMsg, uint16, uint16, bool) {
	if len(ip) < 20 {
		return nil, 0, 0, false
	}
	if ip[0]>>4 != 4 {
		return nil, 0, 0, false
	}
	if ip[9] != 17 { // protocol must be UDP
		return nil, 0, 0, false
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return nil, 0, 0, false
	}
	return parseUDP(ip[ihl:])
}

// parseDNSv6 handles an IPv6 payload (after the Ethernet header).
func parseDNSv6(ip []byte) (*dnsMsg, uint16, uint16, bool) {
	if len(ip) < 40 {
		return nil, 0, 0, false
	}
	if ip[0]>>4 != 6 {
		return nil, 0, 0, false
	}
	if ip[6] != 17 { // next header must be UDP (simplified: no extension headers)
		return nil, 0, 0, false
	}
	return parseUDP(ip[40:])
}

// parseUDP extracts src port, dst port, and DNS payload from a UDP segment.
func parseUDP(udp []byte) (*dnsMsg, uint16, uint16, bool) {
	if len(udp) < 8 {
		return nil, 0, 0, false
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	if srcPort != 53 && dstPort != 53 {
		return nil, 0, 0, false
	}

	payload := udp[8:]
	msg, ok := parseDNS(payload)
	if !ok {
		return nil, 0, 0, false
	}
	return msg, srcPort, dstPort, true
}
