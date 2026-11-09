package bz3

// LZP (Lempel-Ziv Prediction) pre-filter, ported from libbz3.c.
// A 2^18-entry table maps a rolling 4-byte context hash to the last
// position with the same context; matches of at least 40 bytes are
// replaced by the marker byte 0xF2 followed by a length code. A literal
// 0xF2 is escaped as 0xF2 0xFF (only in contexts where a match could be
// signalled, i.e. when the table entry for the current context is set).

const (
	lzpDictionary = 18
	lzpMinMatch   = 40
	lzpMatchByte  = 0xf2
)

func lzpHash(ctx uint32) uint32 {
	return (ctx>>15 ^ ctx ^ ctx>>3) & ((1 << lzpDictionary) - 1)
}

// lzpPackCtx builds the context word from the last 4 bytes ending at
// out[:n]: newest byte in the low byte, matching the reference packing.
func lzpPackCtx(out []byte, n int) uint32 {
	return uint32(out[n-1]) | uint32(out[n-2])<<8 | uint32(out[n-3])<<16 | uint32(out[n-4])<<24
}

// lzpEncode compresses in using the LZP filter. It reports false when
// the filter does not apply (input too small or output would not fit
// below the reference end-of-buffer margin), mirroring lzp_compress.
// The LUT is supplied by the caller and zeroed here.
func lzpEncode(in []byte, lut []int32) ([]byte, bool) {
	n := len(in)
	if n < lzpMinMatch+32 {
		return nil, false
	}
	for i := range lut {
		lut[i] = 0
	}
	upcast := func(pos int) uint32 {
		return uint32(in[pos]) | uint32(in[pos+1])<<8 | uint32(in[pos+2])<<16 | uint32(in[pos+3])<<24
	}
	eob := n - 8 // reference out_eob = out_end - 8
	buf := make([]byte, 0, n)
	buf = append(buf, in[:4]...)
	inPos := 4
	heur := 0
	ctx := uint32(in[3]) | uint32(in[2])<<8 | uint32(in[1])<<16 | uint32(in[0])<<24

	for inPos < n-lzpMinMatch-32 && len(buf) < eob {
		idx := lzpHash(ctx)
		val := lut[idx]
		lut[idx] = int32(inPos)
		matched := false
		if val > 0 {
			ref := int(val)
			if upcast(inPos+lzpMinMatch-4) == upcast(ref+lzpMinMatch-4) && upcast(inPos) == upcast(ref) {
				if !(heur > inPos && upcast(heur) != upcast(ref+(heur-inPos))) {
					length := 4
					for inPos+length < n-lzpMinMatch-32 {
						if upcast(inPos+length) != upcast(ref+length) {
							break
						}
						length += 4
					}
					if length >= lzpMinMatch {
						for t := 0; t < 3; t++ {
							if in[inPos+length] == in[ref+length] {
								length++
							}
						}
						inPos += length
						ctx = lzpPackCtx(in, inPos)
						buf = append(buf, lzpMatchByte)
						length -= lzpMinMatch
						for length >= 254 {
							length -= 254
							buf = append(buf, 254)
							if len(buf) >= eob {
								break
							}
						}
						buf = append(buf, byte(length))
						matched = true
					} else if heur < inPos+length {
						heur = inPos + length
					}
				}
			}
		}
		if matched {
			continue
		}
		next := in[inPos]
		inPos++
		buf = append(buf, next)
		ctx = (ctx << 8) | uint32(next)
		if val > 0 && next == lzpMatchByte {
			buf = append(buf, 255)
		}
	}

	ctx = lzpPackCtx(in, inPos)
	for inPos < n && len(buf) < eob {
		idx := lzpHash(ctx)
		val := lut[idx]
		lut[idx] = int32(inPos)
		next := in[inPos]
		inPos++
		buf = append(buf, next)
		ctx = (ctx << 8) | uint32(next)
		if next == lzpMatchByte && val > 0 {
			buf = append(buf, 255)
		}
	}

	if len(buf) >= eob {
		return nil, false
	}
	return buf, true
}

// lzpDecode expands an LZP-coded stream. maxOut bounds the output size
// (the reference passes the block buffer bound). The LUT is supplied by
// the caller and zeroed here, as in the reference.
func lzpDecode(in []byte, maxOut int, lut []int32) ([]byte, error) {
	if len(in) < 4 {
		return nil, ErrMalformedHeader
	}
	for i := range lut {
		lut[i] = 0
	}
	out := make([]byte, 0, maxOut)
	out = append(out, in[:4]...)
	inPos := 4
	ctx := lzpPackCtx(out, 4)

	for inPos < len(in) && len(out) < maxOut {
		idx := lzpHash(ctx)
		val := lut[idx]
		lut[idx] = int32(len(out))
		if in[inPos] == lzpMatchByte && val > 0 {
			inPos++
			if inPos == len(in) {
				return nil, ErrTruncatedData
			}
			if in[inPos] != 255 {
				maxLen := maxOut - len(out)
				length := lzpMinMatch
				for {
					if inPos == len(in) {
						return nil, ErrTruncatedData
					}
					if length <= maxLen {
						length += int(in[inPos])
					}
					b := in[inPos]
					inPos++
					if b != 254 {
						break
					}
				}
				ref := int(val)
				end := len(out) + length
				if length > maxLen {
					end = maxOut
				}
				for len(out) < end {
					out = append(out, out[ref])
					ref++
				}
				ctx = lzpPackCtx(out, len(out))
			} else {
				inPos++
				ctx = (ctx << 8) | lzpMatchByte
				out = append(out, lzpMatchByte)
			}
		} else {
			b := in[inPos]
			inPos++
			ctx = (ctx << 8) | uint32(b)
			out = append(out, b)
		}
	}
	return out, nil
}
