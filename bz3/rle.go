package bz3

// The modified RLE filter, ported from libbz3.c (mrled). A 32-byte
// bitmask records which byte values have profitable runs; for those
// values, a run is stored as the byte followed by count bytes whose
// values sum (with continuation byte 255) to runLength-1 extra copies.

// rleEncode applies the modified RLE filter (mrlec in the reference):
// a first pass decides per byte value whether collapsing its runs pays
// off, then runs of marked values are stored as byte + count bytes.
func rleEncode(in []byte) []byte {
	var t [256]int32
	pc := -1
	var run int32
	for i := 0; i < len(in); i++ {
		c := int(in[i])
		if c == pc {
			run++
			if run%255 != 0 {
				t[c]++
			}
		} else {
			t[c]--
			run = 0
		}
		pc = c
	}
	out := make([]byte, 0, bound(len(in)))
	for i := 0; i < 32; i++ {
		var c byte
		for j := 0; j < 8; j++ {
			if t[i*8+j] > 0 {
				c |= 1 << j
			}
		}
		out = append(out, c)
	}
	ip := 0
	c, pc := -1, -1
	run = 0
	for {
		if ip < len(in) {
			c = int(in[ip])
			ip++
		} else {
			c = -1
		}
		switch {
		case c == pc:
			run++
		case run > 0 && pc >= 0 && t[pc] > 0:
			out = append(out, byte(pc))
			for ; run > 255; run -= 255 {
				out = append(out, 255)
			}
			out = append(out, byte(run-1))
			run = 1
		default:
			for run++; run > 1; run-- {
				out = append(out, byte(pc))
			}
		}
		pc = c
		if c == -1 {
			break
		}
	}
	return out
}

// rleDecode expands in into exactly outLen bytes.
func rleDecode(in []byte, outLen int) ([]byte, error) {
	if len(in) < 32 {
		return nil, ErrMalformedHeader
	}
	var t [256]bool
	ip := 0
	for i := 0; i < 32; i++ {
		c := in[ip]
		ip++
		for j := 0; j < 8; j++ {
			t[i*8+j] = (c>>j)&1 != 0
		}
	}
	out := make([]byte, 0, outLen)
	for len(out) < outLen && ip < len(in) {
		c := in[ip]
		ip++
		if t[c] {
			run := 1
			for {
				if ip >= len(in) {
					return nil, ErrTruncatedData
				}
				pc := in[ip]
				ip++
				if run <= outLen {
					run += int(pc)
				}
				if pc != 255 {
					break
				}
			}
			for ; run > 0 && len(out) < outLen; run-- {
				out = append(out, c)
			}
		} else {
			out = append(out, c)
		}
	}
	if len(out) != outLen {
		return nil, ErrMalformedHeader
	}
	return out, nil
}
