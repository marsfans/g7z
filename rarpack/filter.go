package rarpack

import "encoding/binary"

// E8/E8E9 filter (RAR5 filter type 2), forward transform.
// The decoder's inverse (Unpack::ApplyFilter) works on signed rel32
// values with a 16 MB address segment (FileSize = 0x1000000):
//
//	S<0:  if S+Offset >= 0 -> S+FileSize, else unchanged
//	S>=0: if S<FileSize    -> S-Offset,   else unchanged
//
// That map is a bijection on int32 for any fixed Offset in [0,FileSize);
// forwardE8E9Addr below is its exact inverse, derived case by case:
//	R >= FileSize          -> S = R            (decoder leaves it)
//	FS-Offset <= R < FS    -> S = R - FileSize (lands in [-Offset,0))
//	-Offset <= R < FS-Offs -> S = R + Offset   (lands in [0,FileSize))
//	R < -Offset            -> S = R            (decoder leaves it)
//
// Offset is the position of the first address byte within the file,
// modulo FileSize — the decoder computes (CurPos+FileOffset)%FileSize
// where CurPos is already past the opcode byte, so positions agree
// globally regardless of how the decoder chunks its writes.

const filterSegment = 0x1000000 // 16 MB
const filterTypeE8E9 = 2

// filterChunkSize is the length of one E8E9 filter block. WinRAR
// emits filter blocks of 64 KB; chunking also keeps every block
// length well below the decoder's MAX_FILTER_BLOCK_SIZE and, unlike
// a single whole-file block, survives decoders that reduce the block
// length modulo the dictionary size.
const filterChunkSize = 65536

// filterChunks splits a file of n bytes into filter blocks as
// [start, length] pairs. Files up to one chunk are split in two
// halves (unless tiny): a single block whose length equals the file
// size is fragile with decoders that clamp the dictionary to the
// file size and then take the length modulo it, which would zero it.
func filterChunks(n int) [][2]int {
	if n <= 0 {
		return nil
	}
	if n <= filterChunkSize {
		if n < 2 {
			return [][2]int{{0, n}}
		}
		h := n / 2
		return [][2]int{{0, h}, {h, n - h}}
	}
	var chunks [][2]int
	for s := 0; s < n; s += filterChunkSize {
		l := filterChunkSize
		if s+l > n {
			l = n - s
		}
		chunks = append(chunks, [2]int{s, l})
	}
	return chunks
}

func forwardE8E9Addr(r int32, offset int32) int32 {
	switch {
	case r >= filterSegment:
		return r
	case r >= filterSegment-offset:
		return r - filterSegment
	case r >= -offset:
		return r + offset
	default:
		return r
	}
}

func inverseE8E9Addr(s int32, offset int32) int32 {
	if s < 0 {
		if s+offset >= 0 {
			return s + filterSegment
		}
		return s
	}
	if s < filterSegment {
		return s - offset
	}
	return s
}

// transformE8E9 returns a filtered copy of data. The scan mirrors the
// decoder loop shape: byte-by-byte, and after an opcode the 4 address
// bytes are skipped (they are never rescanned as opcodes).
func transformE8E9(data []byte) []byte {
	return transformE8E9Region(data, 0, len(data))
}

// transformE8E9Chunked filters data chunk by chunk, exactly as the
// decoder will invert it: each filter block is scanned independently
// (an opcode straddling a chunk boundary is left untransformed on
// both sides), while address offsets use absolute file positions.
func transformE8E9Chunked(data []byte) []byte {
	out := append([]byte(nil), data...)
	for _, ch := range filterChunks(len(data)) {
		seg := transformE8E9Region(out[ch[0]:ch[0]+ch[1]], ch[0], ch[1])
		copy(out[ch[0]:ch[0]+ch[1]], seg)
	}
	return out
}

// transformE8E9Region scans data[0:regionLen] as one filter block whose
// first byte sits at absolute file position base.
func transformE8E9Region(data []byte, base, regionLen int) []byte {
	out := append([]byte(nil), data[:regionLen]...)
	for pos := 0; pos+4 < regionLen; {
		b := out[pos]
		pos++
		if b == 0xe8 || b == 0xe9 {
			off := int32((base + pos) % filterSegment)
			r := int32(binary.LittleEndian.Uint32(out[pos:]))
			binary.LittleEndian.PutUint32(out[pos:], uint32(forwardE8E9Addr(r, off)))
			pos += 4
		}
	}
	return out
}

// inverseE8E9ForTest applies the decoder transform; used by tests.
func inverseE8E9ForTest(data []byte) []byte {
	out := append([]byte(nil), data...)
	for pos := 0; pos+4 < len(out); {
		b := out[pos]
		pos++
		if b == 0xe8 || b == 0xe9 {
			off := int32(pos % filterSegment)
			s := int32(binary.LittleEndian.Uint32(out[pos:]))
			binary.LittleEndian.PutUint32(out[pos:], uint32(inverseE8E9Addr(s, off)))
			pos += 4
		}
	}
	return out
}

func isPE(data []byte) bool {
	return len(data) > 2 && data[0] == 'M' && data[1] == 'Z'
}
