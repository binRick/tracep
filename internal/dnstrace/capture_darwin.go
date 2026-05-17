//go:build darwin

package dnstrace

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// macOS has no AF_PACKET. We use the BPF device (/dev/bpfN): bind it to a
// real Ethernet interface, request immediate delivery, and parse the
// bpf_hdr-framed records out of each read(). PID attribution is not
// available off Linux (see proc_other.go) — queries are still shown.
//
// ioctl request numbers are computed the same way <sys/ioccom.h> does:
//   _IOC(io, g, n, len) = io | ((len & 0x1fff) << 16) | (g << 8) | n
// with IOC_OUT=0x40000000, IOC_IN=0x80000000, IOC_INOUT=0xC0000000,
// IOC_VOID=0x20000000, group 'B' = 0x42.
const (
	iocOut   = 0x40000000
	iocIn    = 0x80000000
	iocInOut = 0xC0000000

	// sizeof(struct ifreq) on macOS = 32 (16-byte name + 16-byte union)
	sizeofIfreq = 32

	biocSBLEN     = iocInOut | (4 << 16) | (0x42 << 8) | 102 // _IOWR('B',102,u_int)
	biocGBLEN     = iocOut | (4 << 16) | (0x42 << 8) | 102   // _IOR('B',102,u_int)
	biocSETIF     = iocIn | (sizeofIfreq << 16) | (0x42 << 8) | 108
	biocIMMEDIATE = iocIn | (4 << 16) | (0x42 << 8) | 112 // _IOW('B',112,u_int)
	biocGDLT      = iocOut | (4 << 16) | (0x42 << 8) | 106 // _IOR('B',106,u_int)
	biocSHDRCMPLT = iocIn | (4 << 16) | (0x42 << 8) | 117  // _IOW('B',117,u_int)

	dltEN10MB = 1 // Ethernet — what parseDNSFromPacket expects
)

type darwinCapture struct {
	fd   int
	buf  []byte // read buffer (size = kernel bpf buffer length)
	rec  []byte // unconsumed bytes from the last read()
	iface string
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) syscall.Errno {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	return e
}

// pickInterface returns an up, non-loopback interface that has an IPv4
// address — i.e. the one carrying real traffic (typically en0).
func pickInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var fallback string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		hasV4 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsGlobalUnicast() {
				hasV4 = true
				break
			}
		}
		if !hasV4 {
			continue
		}
		if len(ifc.Name) >= 2 && ifc.Name[:2] == "en" {
			return ifc.Name, nil // prefer Ethernet/Wi-Fi
		}
		if fallback == "" {
			fallback = ifc.Name
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no up non-loopback IPv4 interface found")
}

func openCapture() (*darwinCapture, error) {
	iface, err := pickInterface()
	if err != nil {
		return nil, err
	}

	var fd int
	var openErr error
	for i := 0; i < 256; i++ {
		fd, openErr = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY, 0)
		if openErr == nil {
			break
		}
	}
	if openErr != nil {
		return nil, fmt.Errorf("open /dev/bpf*: %v\nHint: run with sudo", openErr)
	}

	// Buffer length must be set before binding the interface.
	blen := uint32(32768)
	if e := ioctl(fd, biocSBLEN, unsafe.Pointer(&blen)); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCSBLEN: %v", e)
	}
	if e := ioctl(fd, biocGBLEN, unsafe.Pointer(&blen)); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCGBLEN: %v", e)
	}

	// Bind to the interface (struct ifreq: name in the first 16 bytes).
	var ifreq [sizeofIfreq]byte
	copy(ifreq[:15], iface)
	if e := ioctl(fd, biocSETIF, unsafe.Pointer(&ifreq[0])); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCSETIF %s: %v", iface, e)
	}

	// Deliver packets as soon as they arrive instead of buffering.
	one := uint32(1)
	if e := ioctl(fd, biocIMMEDIATE, unsafe.Pointer(&one)); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCIMMEDIATE: %v", e)
	}
	_ = ioctl(fd, biocSHDRCMPLT, unsafe.Pointer(&one)) // best-effort

	var dlt uint32
	if e := ioctl(fd, biocGDLT, unsafe.Pointer(&dlt)); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("BIOCGDLT: %v", e)
	}
	if dlt != dltEN10MB {
		syscall.Close(fd)
		return nil, fmt.Errorf("interface %s link type %d is not Ethernet (DLT_EN10MB); unsupported", iface, dlt)
	}

	return &darwinCapture{fd: fd, buf: make([]byte, blen), iface: iface}, nil
}

// bpfWordAlign rounds up to the BPF alignment (sizeof(int32)=4 on macOS).
func bpfWordAlign(x int) int { return (x + 3) &^ 3 }

// next returns the next captured Ethernet frame, refilling from the BPF
// device when the current read buffer is exhausted. One read() can carry
// many bpf_hdr-prefixed records.
func (c *darwinCapture) next() ([]byte, error) {
	for {
		// Parse the next record out of whatever we already read.
		for len(c.rec) >= 18 { // 18 = nominal sizeof(struct bpf_hdr)
			caplen := int(binary.LittleEndian.Uint32(c.rec[8:12]))
			hdrlen := int(binary.LittleEndian.Uint16(c.rec[16:18]))
			if hdrlen < 18 || hdrlen+caplen > len(c.rec) {
				c.rec = nil // malformed / truncated — resync on next read
				break
			}
			frame := c.rec[hdrlen : hdrlen+caplen]
			advance := bpfWordAlign(hdrlen + caplen)
			if advance >= len(c.rec) {
				c.rec = nil
			} else {
				c.rec = c.rec[advance:]
			}
			out := make([]byte, len(frame))
			copy(out, frame)
			return out, nil
		}

		n, err := syscall.Read(c.fd, c.buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if n <= 0 {
			continue
		}
		c.rec = c.buf[:n]
	}
}

func (c *darwinCapture) Close() error { return syscall.Close(c.fd) }
