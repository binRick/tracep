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
// bpf_hdr-framed records out of each read(). PID attribution on macOS is
// provided by proc_darwin.go via an lsof UDP-port→PID map (own-user sockets
// only when non-root); queries that can't be attributed are still shown.
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

	fd := -1
	var openErr error
	for i := 0; i < 256; i++ {
		f, e := syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY, 0)
		if e == nil {
			fd, openErr = f, nil
			break
		}
		// Report the real barrier: a permission error on the low-numbered
		// nodes that actually exist, rather than the ENOENT we hit once we
		// run past the highest /dev/bpfN that exists (which would otherwise
		// mislead with "no such file or directory" on a non-root run).
		if openErr == nil || e == syscall.EACCES || e == syscall.EPERM {
			openErr = e
		}
	}
	if fd < 0 {
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

// bpfNextRecord splits the first bpf_hdr-framed record out of rec. macOS
// struct bpf_hdr is: bh_tstamp[0:8], bh_caplen[8:12], bh_datalen[12:16],
// bh_hdrlen[16:18] (host byte order). bh_hdrlen is the (aligned) offset to
// the captured frame; the next record starts at BPF_WORDALIGN(hdrlen+caplen).
// Returns the frame, the remaining buffer, and ok=false when no complete
// record is present (caller should read more / resync).
//
// Pure and unit-tested (capture_darwin_test.go) because the framing math is
// the most error-prone part and can't be exercised without root + /dev/bpf.
func bpfNextRecord(rec []byte) (frame, rest []byte, ok bool) {
	if len(rec) < 18 { // 18 = nominal sizeof(struct bpf_hdr)
		return nil, nil, false
	}
	caplen := int(binary.LittleEndian.Uint32(rec[8:12]))
	hdrlen := int(binary.LittleEndian.Uint16(rec[16:18]))
	if hdrlen < 18 || caplen < 0 || hdrlen+caplen > len(rec) {
		return nil, nil, false
	}
	frame = rec[hdrlen : hdrlen+caplen]
	advance := bpfWordAlign(hdrlen + caplen)
	if advance >= len(rec) {
		rest = nil
	} else {
		rest = rec[advance:]
	}
	return frame, rest, true
}

// next returns the next captured Ethernet frame, refilling from the BPF
// device when the current read buffer is exhausted. One read() can carry
// many bpf_hdr-prefixed records.
func (c *darwinCapture) next() ([]byte, error) {
	for {
		if frame, rest, ok := bpfNextRecord(c.rec); ok {
			c.rec = rest
			out := make([]byte, len(frame))
			copy(out, frame)
			return out, nil
		}
		c.rec = nil // exhausted or malformed — resync on next read

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
