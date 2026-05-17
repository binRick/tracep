//go:build linux

package dnstrace

import (
	"fmt"
	"syscall"
)

// linuxCapture wraps a raw AF_PACKET socket that receives every Ethernet
// frame on every interface — one frame per Recvfrom.
type linuxCapture struct {
	fd  int
	buf []byte
}

func openCapture() (*linuxCapture, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %v\nHint: run as root or: sudo setcap cap_net_raw+eip tracep", err)
	}
	return &linuxCapture{fd: fd, buf: make([]byte, 65536)}, nil
}

// next returns the next captured Ethernet frame.
func (c *linuxCapture) next() ([]byte, error) {
	n, _, err := syscall.Recvfrom(c.fd, c.buf, 0)
	if err != nil {
		return nil, err
	}
	return c.buf[:n], nil
}

func (c *linuxCapture) Close() error { return syscall.Close(c.fd) }

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }
