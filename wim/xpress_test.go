package wim

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

// decode7zStyle decodes a chunk the way 7-Zip's
// Decode_WithExceedWrite does, because that decoder is stricter
// than wimlib's: it preloads two bitstream words, reloads one
// word whenever its consumed-bit counter passes 16, reads
// extended match lengths from the raw input pointer, and only
// succeeds when, once the output is full, one more symbol
// decodes to 256 with an all-zero bit register and the input
// consumed exactly. Chunks lacking the end symbol or the exact
// length fail here even though lenient decoders accept them.
func decode7zStyle(t *testing.T, chunk []byte, wantLen int) []byte {
	t.Helper()
	if len(chunk) < xpressSymbols/2+4 {
		t.Fatalf("chunk too short: %d", len(chunk))
	}
	var lens [xpressSymbols]byte
	for i := 0; i < xpressSymbols/2; i++ {
		lens[2*i] = chunk[i] & 0xF
		lens[2*i+1] = chunk[i] >> 4
	}
	dec, err := newHuffDecoder(&lens)
	if err != nil {
		t.Fatal(err)
	}
	in := chunk[xpressSymbols/2:]
	pos := 0 // input pointer, 7z's `in`
	load16 := func() uint32 {
		if pos+2 > len(in) {
			return 0
		}
		v := uint32(binary.LittleEndian.Uint16(in[pos:]))
		pos += 2
		return v
	}
	value := load16()<<16 | load16()
	bitPos := 0
	normalize := func() {
		if bitPos > 16 {
			bitPos -= 16
			value |= load16() << uint(bitPos)
		}
	}
	out := make([]byte, 0, wantLen)
	for {
		// Huffman decode from the top of the register.
		code, first, sym := 0, 0, -1
		for l := 1; l <= xpressMaxLen; l++ {
			bit := value >> 31
			value <<= 1
			bitPos++
			code = code<<1 | int(bit)
			if code-first < dec.counts[l] {
				sym = int(dec.sorted[dec.offs[l]+code-first])
				break
			}
			first = (first + dec.counts[l]) << 1
		}
		if sym < 0 {
			t.Fatal("invalid Huffman code")
		}
		normalize()
		if len(out) >= wantLen {
			if sym != 256 || value != 0 || pos != len(in) {
				t.Fatalf("bad chunk termination: sym=%d value=%#x consumed=%d of %d stream bytes",
					sym, value, pos, len(in))
			}
			return out
		}
		if sym < 256 {
			out = append(out, byte(sym))
			continue
		}
		lenSlot := sym & 0xF
		posSlot := (sym >> 4) & 0xF
		length := lenSlot
		if lenSlot == 0xF {
			if pos >= len(in) {
				t.Fatal("length byte past end of chunk")
			}
			length = int(in[pos])
			pos++
			if length == 0xFF {
				if pos+2 > len(in) {
					t.Fatal("length u16 past end of chunk")
				}
				length = int(binary.LittleEndian.Uint16(in[pos:]))
				pos += 2
			} else {
				length += 0xF
			}
		}
		length += xpressMinMatch
		var dist int
		if posSlot == 0 {
			dist = 1
		} else {
			d := value >> (32 - uint(posSlot))
			value <<= uint(posSlot)
			bitPos += posSlot
			dist = int(d) + (1 << uint(posSlot))
			normalize()
		}
		if dist < 1 || dist > len(out) {
			t.Fatalf("match distance %d out of range at %d", dist, len(out))
		}
		for i := 0; i < length; i++ {
			out = append(out, out[len(out)-dist])
		}
	}
}

func xpressCases() map[string][]byte {
	rng := rand.New(rand.NewSource(42))
	rnd := make([]byte, 5000)
	rng.Read(rnd)
	period := make([]byte, 100000)
	for i := range period {
		period[i] = byte(i % 15)
	}
	return map[string][]byte{
		"one byte":   []byte("x"),
		"hello":      bytes.Repeat([]byte("Hello formats!\n"), 50),
		"text":       bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 300),
		"random":     rnd,
		"zeros":      make([]byte, 32768),
		"period 15":  period, // maximum-length matches, u16 length form
		"abc repeat": bytes.Repeat([]byte("abcdefgh"), 9000),
	}
}

func TestXpressRoundtrip(t *testing.T) {
	for name, data := range xpressCases() {
		comp, err := xpressCompressChunk(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(comp) >= len(data) {
			continue // stored raw by the caller; nothing to decode
		}
		dec, err := xpressDecompressChunk(comp, len(data))
		if err != nil {
			t.Fatalf("%s: own decoder: %v", name, err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("%s: own decoder mismatch", name)
		}
		if got := decode7zStyle(t, comp, len(data)); !bytes.Equal(got, data) {
			t.Fatalf("%s: strict (7z-style) decoder mismatch", name)
		}
	}
}
