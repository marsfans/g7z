package rarpack

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestE8E9AddrBijection(t *testing.T) {
	offsets := []int32{0, 1, 2, 100, 65535, 0x800000, 0xfffffe, 0xffffff}
	rng := rand.New(rand.NewSource(7))
	check := func(r, off int32) {
		s := forwardE8E9Addr(r, off)
		if got := inverseE8E9Addr(s, off); got != r {
			t.Fatalf("off %d: R %d -> S %d -> %d", off, r, s, got)
		}
	}
	for _, off := range offsets {
		// boundary values
		for _, r := range []int32{-0x80000000, -0x1000000, -off - 1, -off, -off + 1, -1, 0, 1,
			filterSegment - off - 1, filterSegment - off, filterSegment - off + 1,
			filterSegment - 1, filterSegment, filterSegment + 1, 0x7fffffff} {
			check(r, off)
		}
		for i := 0; i < 20000; i++ {
			check(int32(rng.Uint32()), off)
		}
	}
}

func TestE8E9BufferRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	for trial := 0; trial < 50; trial++ {
		n := 100 + rng.Intn(5000)
		buf := make([]byte, n)
		rng.Read(buf)
		// plant opcodes densely
		for i := 0; i+5 < n; i += 3 {
			buf[i] = 0xe8
			if i%2 == 0 {
				buf[i] = 0xe9
			}
			binary.LittleEndian.PutUint32(buf[i+1:], rng.Uint32())
		}
		tr := transformE8E9(buf)
		back := inverseE8E9ForTest(tr)
		if !bytes.Equal(back, buf) {
			t.Fatalf("trial %d: buffer round trip failed", trial)
		}
	}
}

// inverseE8E9Chunked simulates the decoder: invert each filter block
// independently, with address offsets from absolute file positions.
func inverseE8E9Chunked(data []byte) []byte {
	out := append([]byte(nil), data...)
	for _, ch := range filterChunks(len(data)) {
		seg := out[ch[0] : ch[0]+ch[1]]
		for pos := 0; pos+4 < len(seg); {
			b := seg[pos]
			pos++
			if b == 0xe8 || b == 0xe9 {
				off := int32((ch[0] + pos) % filterSegment)
				s := int32(binary.LittleEndian.Uint32(seg[pos:]))
				binary.LittleEndian.PutUint32(seg[pos:], uint32(inverseE8E9Addr(s, off)))
				pos += 4
			}
		}
	}
	return out
}

func TestE8E9ChunkedRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	// Sizes around chunk boundaries, incl. straddling opcodes.
	for _, n := range []int{1, 2, 5, 100, 65535, 65536, 65537, 131072, 200000} {
		buf := make([]byte, n)
		r.Read(buf)
		// Plant opcodes at strategic spots: chunk starts/ends, straddles.
		for _, p := range []int{0, 1, n / 2, 65532, 65533, 65534, 65535, 65536, n - 5, n - 1} {
			if p >= 0 && p < n {
				buf[p] = 0xe8
			}
		}
		enc := transformE8E9Chunked(buf)
		dec := inverseE8E9Chunked(enc)
		if !bytes.Equal(dec, buf) {
			t.Fatalf("size %d: chunked round trip mismatch", n)
		}
	}
	// Dense-opcode buffer larger than two chunks.
	buf := bytes.Repeat([]byte{0xe8, 0x78, 0x56, 0x34, 0x12}, 40000)
	if dec := inverseE8E9Chunked(transformE8E9Chunked(buf)); !bytes.Equal(dec, buf) {
		t.Fatal("dense chunked round trip mismatch")
	}
}
