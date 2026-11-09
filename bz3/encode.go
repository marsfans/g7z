package bz3

import (
	"bytes"
	"io"
)

// encoder holds the reusable per-stream encoding state.
type encoder struct {
	cm  cmState
	lut []int32
}

func newEncoder() *encoder {
	return &encoder{lut: make([]int32, 1<<lzpDictionary)}
}

// encodeBlock encodes one block, mirroring bz3_encode_block: RLE first,
// then LZP, then BWT + arithmetic coding; blocks under 64 bytes are
// stored as literals.
func (e *encoder) encodeBlock(data []byte) []byte {
	crc := blockCRC(data)
	if len(data) < 64 {
		out := make([]byte, 8, len(data)+8)
		writeS32(out[0:], int32(crc))
		writeS32(out[4:], -1)
		return append(out, data...)
	}

	var model byte
	cur := data
	var lzpSize, rleSize int
	if r := rleEncode(cur); len(r) < len(cur) {
		model |= 4
		rleSize = len(r)
		cur = r
	}
	if l, ok := lzpEncode(cur, e.lut); ok && len(l) < len(cur) {
		model |= 2
		lzpSize = len(l)
		cur = l
	}

	L, idx := bwtForward(cur)
	e.cm.begin()
	ac := e.cm.encodeBytes(L)

	hdr := 9
	if model&2 != 0 {
		hdr += 4
	}
	if model&4 != 0 {
		hdr += 4
	}
	out := make([]byte, 0, hdr+len(ac))
	var tmp [4]byte
	writeS32(tmp[:], int32(crc))
	out = append(out, tmp[:]...)
	writeS32(tmp[:], int32(idx))
	out = append(out, tmp[:]...)
	out = append(out, model)
	if model&2 != 0 {
		writeS32(tmp[:], int32(lzpSize))
		out = append(out, tmp[:]...)
	}
	if model&4 != 0 {
		writeS32(tmp[:], int32(rleSize))
		out = append(out, tmp[:]...)
	}
	return append(out, ac...)
}

// Compress writes data from r to w in the bzip3 CLI file format using
// blocks of up to blockSize bytes. A blockSize of 0 selects the default.
func Compress(w io.Writer, r io.Reader, blockSize int) error {
	wr, err := NewWriter(w, blockSize)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wr, r); err != nil {
		return err
	}
	return wr.Close()
}

// CompressBytes compresses a complete in-memory buffer.
func CompressBytes(in []byte, blockSize int) ([]byte, error) {
	var out bytes.Buffer
	if err := Compress(&out, bytes.NewReader(in), blockSize); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
