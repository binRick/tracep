//go:build darwin

package dnstrace

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// makeRec builds one bpf_hdr-framed record exactly as the macOS kernel
// lays it out: a hdrlen-byte header (caplen@8, datalen@12, hdrlen@16),
// the frame, then padding so the record occupies BPF_WORDALIGN bytes.
func makeRec(hdrlen int, frame []byte) []byte {
	rec := make([]byte, hdrlen)
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(frame)))
	binary.LittleEndian.PutUint16(rec[16:18], uint16(hdrlen))
	rec = append(rec, frame...)
	for len(rec) < bpfWordAlign(hdrlen+len(frame)) {
		rec = append(rec, 0)
	}
	return rec
}

func TestBPFNextRecord_Single(t *testing.T) {
	frame := []byte{0xde, 0xad, 0xbe, 0xef}
	got, rest, ok := bpfNextRecord(makeRec(18, frame))
	if !ok {
		t.Fatal("ok=false for a valid record")
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("frame = %x, want %x", got, frame)
	}
	if len(rest) != 0 {
		t.Fatalf("rest = %x, want empty", rest)
	}
}

// hdrlen 20 = BPF_WORDALIGN(sizeof(struct bpf_hdr)=18) — the real macOS
// value, with 2 pad bytes between the header and the frame.
func TestBPFNextRecord_AlignedHeader(t *testing.T) {
	frame := []byte{1, 2, 3, 4, 5}
	got, _, ok := bpfNextRecord(makeRec(20, frame))
	if !ok || !bytes.Equal(got, frame) {
		t.Fatalf("ok=%v frame=%x, want %x", ok, got, frame)
	}
}

// Two records back-to-back, the first with a caplen that forces inter-record
// alignment padding (18+5=23 -> WORDALIGN 24, i.e. 1 pad byte).
func TestBPFNextRecord_MultiWithPadding(t *testing.T) {
	f1 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee} // 5 bytes -> padded
	f2 := []byte{0x11, 0x22, 0x33, 0x44}       // 4 bytes -> exact
	buf := append(makeRec(18, f1), makeRec(18, f2)...)

	g1, rest, ok := bpfNextRecord(buf)
	if !ok || !bytes.Equal(g1, f1) {
		t.Fatalf("record 1: ok=%v frame=%x, want %x", ok, g1, f1)
	}
	g2, rest2, ok := bpfNextRecord(rest)
	if !ok || !bytes.Equal(g2, f2) {
		t.Fatalf("record 2: ok=%v frame=%x, want %x", ok, g2, f2)
	}
	if len(rest2) != 0 {
		t.Fatalf("trailing rest = %x, want empty", rest2)
	}
}

func TestBPFNextRecord_Rejects(t *testing.T) {
	if _, _, ok := bpfNextRecord(make([]byte, 10)); ok {
		t.Fatal("accepted a sub-header buffer")
	}
	// caplen claims more bytes than the buffer holds.
	bad := make([]byte, 18)
	binary.LittleEndian.PutUint32(bad[8:12], 9999)
	binary.LittleEndian.PutUint16(bad[16:18], 18)
	if _, _, ok := bpfNextRecord(bad); ok {
		t.Fatal("accepted a record with caplen past the buffer")
	}
	// hdrlen below the minimum header size.
	bad2 := make([]byte, 18)
	binary.LittleEndian.PutUint16(bad2[16:18], 4)
	if _, _, ok := bpfNextRecord(bad2); ok {
		t.Fatal("accepted a record with an impossibly small hdrlen")
	}
}

func TestBPFNextRecord_ExactFit(t *testing.T) {
	frame := []byte{9, 9, 9, 9}
	rec := makeRec(18, frame) // 18+4=22 -> WORDALIGN 24
	_, rest, ok := bpfNextRecord(rec)
	if !ok {
		t.Fatal("ok=false for exact-fit record")
	}
	if rest != nil {
		t.Fatalf("rest = %x, want nil when the record consumes the buffer", rest)
	}
}
