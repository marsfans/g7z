package bz3

// The entropy coder: a bitwise arithmetic coder with a context-mixing
// model, following Matt Mahoney's DCE outline as implemented in libbz3.c.
// This is a line-by-line port; the model state evolution must match the
// reference bit-for-bit or the arithmetic code stream desynchronises.
//
// Model state:
//   - C0[ctx]: order-0 bit probabilities per binary-tree node (1..255)
//   - C1[prev][ctx]: probabilities conditioned on the previous byte
//   - C2[2*ctx+f][j]: a secondary-symbol-estimation (SSE) table that
//     remaps the mixed prediction before it drives the coder
//
// Probabilities are u16 fixed point (1<<15 = 0.5).

type cmState struct {
	c0 [256]uint16
	c1 [256 * 256]uint16 // [prevByte][ctx]
	c2 [512 * 17]uint16  // [2*ctx + f][j]
}

func update0(p uint16, x uint) uint16 { return p - (p >> x) }
func update1(p uint16, x uint) uint16 { return p + ((p ^ 65535) >> x) }

// begin resets the model to its initial state, as at the start of a block.
func (s *cmState) begin() {
	for i := range s.c0 {
		s.c0[i] = 1 << 15
	}
	for i := range s.c1 {
		s.c1[i] = 1 << 15
	}
	for i := 0; i < 2; i++ {
		for j := 0; j < 256; j++ {
			for k := 0; k < 17; k++ {
				v := (k << 12)
				if k == 16 {
					v--
				}
				s.c2[(2*j+i)*17+k] = uint16(v)
			}
		}
	}
}

// predict returns the mixed probability estimate for the next bit at tree
// node ctx, given the two previous bytes and the run flag.
func (s *cmState) predict(c1, c2 uint32, f, ctx int) (p, j, ssep int) {
	p0 := int(s.c0[ctx])
	p1 := int(s.c1[c1*256+uint32(ctx)])
	p2 := int(s.c1[c2*256+uint32(ctx)])
	p = ((p0+p1)*7 + p2 + p2) >> 4

	j = p >> 12
	x1 := int(s.c2[(2*ctx+f)*17+j])
	x2 := int(s.c2[(2*ctx+f)*17+j+1])
	ssep = x1 + (((x2 - x1) * (p & 4095)) >> 12)
	return p, j, ssep
}

// update adapts the model after a bit is coded. Only the C1 row of the
// immediately preceding byte is updated; C1[c2] is read-only prediction
// input, exactly as in the reference.
func (s *cmState) update(bit bool, c1 uint32, f, ctx, j int) {
	if bit {
		s.c0[ctx] = update1(s.c0[ctx], 2)
		s.c1[c1*256+uint32(ctx)] = update1(s.c1[c1*256+uint32(ctx)], 4)
		s.c2[(2*ctx+f)*17+j] = update1(s.c2[(2*ctx+f)*17+j], 6)
		s.c2[(2*ctx+f)*17+j+1] = update1(s.c2[(2*ctx+f)*17+j+1], 6)
	} else {
		s.c0[ctx] = update0(s.c0[ctx], 2)
		s.c1[c1*256+uint32(ctx)] = update0(s.c1[c1*256+uint32(ctx)], 4)
		s.c2[(2*ctx+f)*17+j] = update0(s.c2[(2*ctx+f)*17+j], 6)
		s.c2[(2*ctx+f)*17+j+1] = update0(s.c2[(2*ctx+f)*17+j+1], 6)
	}
}

// encodeBytes arithmetic-codes buf and returns the coded bytes.
func (s *cmState) encodeBytes(buf []byte) []byte {
	out := make([]byte, 0, len(buf)/2+64)
	var high, low uint32 = 0xFFFFFFFF, 0
	var c1, c2, run uint32

	for _, ch := range buf {
		c := uint32(ch)
		if c1 == c2 {
			run++
		} else {
			run = 0
		}
		f := 0
		if run > 2 {
			f = 1
		}
		ctx := 1
		for ctx < 256 {
			p, j, ssep := s.predict(c1, c2, f, ctx)
			prob := uint64(ssep*3 + p)
			if c&128 != 0 {
				high = low + uint32((uint64(high-low)*prob)>>18)
				for (low ^ high) < (1 << 24) {
					out = append(out, byte(low>>24))
					low <<= 8
					high = (high << 8) + 0xFF
				}
				s.update(true, c1, f, ctx, j)
				ctx += ctx + 1
			} else {
				low += uint32((uint64(high-low)*prob)>>18) + 1
				for (low ^ high) < (1 << 24) {
					out = append(out, byte(low>>24))
					low <<= 8
					high = (high << 8) + 0xFF
				}
				s.update(false, c1, f, ctx, j)
				ctx += ctx
			}
			c <<= 1
		}
		c2 = c1
		c1 = uint32(ctx & 255)
	}

	for i := 0; i < 4; i++ {
		out = append(out, byte(low>>24))
		low <<= 8
	}
	return out
}

// decodeBytes decodes size bytes of arithmetic-coded data from in.
// Reading past the end of in yields -1 per read, as in the reference.
func (s *cmState) decodeBytes(in []byte, out []byte) {
	inputPtr := 0
	readIn := func() int32 {
		if inputPtr < len(in) {
			v := int32(in[inputPtr])
			inputPtr++
			return v
		}
		return -1
	}

	var high, low, code uint32 = 0xFFFFFFFF, 0, 0
	var c1, c2, run uint32

	for i := 0; i < 4; i++ {
		code = (code << 8) + uint32(readIn())
	}

	for i := range out {
		if c1 == c2 {
			run++
		} else {
			run = 0
		}
		f := 0
		if run > 2 {
			f = 1
		}
		ctx := 1
		for ctx < 256 {
			p, j, ssep := s.predict(c1, c2, f, ctx)
			mid := low + uint32((uint64(high-low)*uint64(ssep*3+p))>>18)
			bit := code <= mid
			if bit {
				high = mid
			} else {
				low = mid + 1
			}
			for (low ^ high) < (1 << 24) {
				low <<= 8
				high = (high << 8) + 255
				code = (code << 8) + uint32(readIn())
			}
			s.update(bit, c1, f, ctx, j)
			if bit {
				ctx += ctx + 1
			} else {
				ctx += ctx
			}
		}
		c2 = c1
		out[i] = byte(ctx & 255)
		c1 = uint32(ctx & 255)
	}
}
