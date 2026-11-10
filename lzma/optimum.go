// Copyright 2014-2022 Ulrich Kunitz. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

import (
	"encoding/binary"
	"math/bits"
)

// Optimal (price-guided) parsing for the LZMA encoder, ported from
// liblzma's lzma_encoder_optimum_normal.c (Igor Pavlov, 0BSD). The
// parser evaluates literal, match and rep-match candidates for a
// window of upcoming positions using bit prices derived from the
// live encoder probabilities, and emits the cheapest path.
//
// The match candidate finder is a hash-chain matcher with a bounded
// search depth (unlike the package's BinaryTree matcher it cannot
// degenerate on repetitive data).

const (
	optInfinityPrice = 1 << 30
	optSlots         = 8192
	backLiteral      = ^uint32(0)
)

// optimal is one slot of the optimum path table: it describes the
// cheapest known encoding of the prefix ending at this slot.
type optimal struct {
	price          uint32
	state          uint32
	backs          [4]uint32
	posPrev        uint32
	backPrev       uint32
	prev1IsLiteral bool
	prev2          bool
	posPrev2       uint32
	backPrev2      uint32
}

func makeLiteral(o *optimal) {
	o.backPrev = backLiteral
	o.prev1IsLiteral = false
}

func makeShortRep(o *optimal) {
	o.backPrev = 0
	o.prev1IsLiteral = false
}

// Pure LZMA state transitions (mirrors of the state methods).
func stateAfterLiteral(s uint32) uint32 {
	switch {
	case s < 4:
		return 0
	case s < 10:
		return s - 3
	}
	return s - 6
}

func stateAfterMatch(s uint32) uint32 {
	if s < 7 {
		return 7
	}
	return 10
}

func stateAfterRep(s uint32) uint32 {
	if s < 7 {
		return 8
	}
	return 11
}

func stateAfterShortRep(s uint32) uint32 {
	if s < 7 {
		return 9
	}
	return 11
}

func isLiteralState(s uint32) bool { return s < 7 }

// distSlot computes the position slot for a distance offset
// (distance - 1), mirroring distCodec.Encode.
func distSlot(dist uint32) uint32 {
	if dist < startPosModel {
		return dist
	}
	bits := uint32(30 - nlz32(dist))
	return startPosModel - 2 + (bits << 1) + ((dist >> bits) & 1)
}

// ---------- pricer ----------

// optPricer holds price tables derived from the live probabilities.
// They are rebuilt periodically while parsing.
type optPricer struct {
	lenPrices      [1 << maxPosBits][maxMatchLen - minMatchLen + 1]uint32
	repLenPrices   [1 << maxPosBits][maxMatchLen - minMatchLen + 1]uint32
	distSlotPrices [lenStates][64]uint32
	distPrices     [lenStates][128]uint32
	alignPrices    [1 << alignBits]uint32
}

func fillLenPrices(lc *lengthCodec, out *[1 << maxPosBits][maxMatchLen - minMatchLen + 1]uint32) {
	a0 := bit0Price(lc.choice[0])
	a1 := bit1Price(lc.choice[0])
	b0 := a1 + bit0Price(lc.choice[1])
	b1 := a1 + bit1Price(lc.choice[1])
	for ps := range out {
		for i := 0; i < 8; i++ {
			out[ps][i] = a0 + bittreePrice(lc.low[ps].probs, 3, uint32(i))
		}
		for i := 8; i < 16; i++ {
			out[ps][i] = b0 + bittreePrice(lc.mid[ps].probs, 3, uint32(i-8))
		}
		for i := 16; i < maxMatchLen-minMatchLen+1; i++ {
			out[ps][i] = b1 + bittreePrice(lc.high.probs, 8, uint32(i-16))
		}
	}
}

func (p *optPricer) fill(st *state) {
	fillLenPrices(&st.lenCodec, &p.lenPrices)
	fillLenPrices(&st.repLenCodec, &p.repLenPrices)
	dc := &st.distCodec
	for ds := 0; ds < lenStates; ds++ {
		for slot := 0; slot < 64; slot++ {
			pr := bittreePrice(dc.posSlotCodecs[ds].probs, posSlotBits, uint32(slot))
			if slot >= endPosModel {
				pr += directPrice(uint32((slot >> 1) - 1 - alignBits))
			}
			p.distSlotPrices[ds][slot] = pr
		}
		for i := 0; i < startPosModel; i++ {
			p.distPrices[ds][i] = p.distSlotPrices[ds][i]
		}
	}
	for i := startPosModel; i < 128; i++ {
		slot := distSlot(uint32(i))
		footerBits := (slot >> 1) - 1
		base := (2 | (slot & 1)) << footerBits
		pr := bittreeReversePrice(dc.posModel[slot-startPosModel].probs,
			uint(footerBits), uint32(i)-base)
		for ds := 0; ds < lenStates; ds++ {
			p.distPrices[ds][i] = pr + p.distSlotPrices[ds][slot]
		}
	}
	for i := range p.alignPrices {
		p.alignPrices[i] = bittreeReversePrice(dc.alignCodec.probs,
			alignBits, uint32(i))
	}
}

// distLenPrice returns the price of a normal match (distance offset
// dist, match length len) excluding the isMatch/isRep bits.
func (p *optPricer) distLenPrice(dist, len, posState uint32) uint32 {
	ds := lenState(len - minMatchLen)
	var pr uint32
	if dist < 128 {
		pr = p.distPrices[ds][dist]
	} else {
		pr = p.distSlotPrices[ds][distSlot(dist)] + p.alignPrices[dist&15]
	}
	return pr + p.lenPrices[posState][len-minMatchLen]
}

// distParts returns the distance part of the match price for every
// length state, so callers evaluating one distance at many lengths
// can hoist it out of the length loop:
// distLenPrice(dist, len, ps) == distParts(dist)[lenState(len-2)] +
// lenPrices[ps][len-2].
func (p *optPricer) distParts(dist uint32) (parts [4]uint32) {
	for ds := uint32(0); ds < 4; ds++ {
		if dist < 128 {
			parts[ds] = p.distPrices[ds][dist]
		} else {
			parts[ds] = p.distSlotPrices[ds][distSlot(dist)] + p.alignPrices[dist&15]
		}
	}
	return parts
}

// pureRepPrice returns the price of the rep selection bits for
// rep index i (excluding length and the isMatch/isRep bits).
func pureRepPrice(st *state, i, stIdx, posState uint32) uint32 {
	if i == 0 {
		return bit0Price(st.isRepG0[stIdx]) +
			bit1Price(st.isRepG0Long[(stIdx<<maxPosBits)|posState])
	}
	pr := bit1Price(st.isRepG0[stIdx])
	if i == 1 {
		return pr + bit0Price(st.isRepG1[stIdx])
	}
	return pr + bit1Price(st.isRepG1[stIdx]) +
		bitPrice(st.isRepG2[stIdx], i-2)
}

// shortRepPrice returns the price of the short-rep selection bits.
func shortRepPrice(st *state, stIdx, posState uint32) uint32 {
	return bit0Price(st.isRepG0[stIdx]) +
		bit0Price(st.isRepG0Long[(stIdx<<maxPosBits)|posState])
}

// literalPrice mirrors literalCodec.Encode, accumulating prices
// instead of emitting bits.
func literalPrice(st *state, pos int64, prevByte byte, matchMode bool,
	matchByte, symbol byte) uint32 {
	litState := st.litState(prevByte, pos)
	probs := st.litCodec.probs[litState*0x300 : litState*0x300+0x300]
	price := uint32(0)
	r := uint32(symbol)
	sym := uint32(1)
	if matchMode {
		m := uint32(matchByte)
		for {
			matchBit := (m >> 7) & 1
			m <<= 1
			bit := (r >> 7) & 1
			r <<= 1
			price += bitPrice(probs[((1+matchBit)<<8)|sym], bit)
			sym = (sym << 1) | bit
			if matchBit != bit || sym >= 0x100 {
				break
			}
		}
	}
	for sym < 0x100 {
		bit := (r >> 7) & 1
		r <<= 1
		price += bitPrice(probs[sym], bit)
		sym = (sym << 1) | bit
	}
	return price
}

// ---------- match finder ----------

type optMatch struct {
	len  uint32
	dist uint32 // distance offset (distance - 1)
}

// optFinder is a hash-chain match finder over the encoder
// dictionary. It satisfies the matcher interface so it can be
// installed in the encoder dictionary, but the optimal parser drives
// it directly; Write and NextOp are not used by the encoder loop.
type optFinder struct {
	dict    *encoderDict
	head    []int32
	prev    []int32
	next    int64
	nextIdx int
	nextCyc int64
	idxOK   bool
	depth   int
	cap     int
}

func newOptFinder(dictCap, depth int) *optFinder {
	f := &optFinder{
		head:  make([]int32, 1<<16),
		prev:  make([]int32, dictCap),
		depth: depth,
		cap:   dictCap,
	}
	for i := range f.head {
		f.head[i] = -1
	}
	return f
}

func (f *optFinder) SetDict(d *encoderDict) { f.dict = d }

// Write implements io.Writer for the matcher interface. The parser
// manages insertion itself, so discarded bytes are ignored here.
func (f *optFinder) Write(p []byte) (int, error) { return len(p), nil }

// NextOp implements the matcher interface. It is never called in
// optimal mode.
func (f *optFinder) NextOp(rep [4]uint32) operation {
	panic("lzma: optFinder.NextOp called in optimal mode")
}

// byteAt returns the byte at absolute stream position pos within the
// dictionary's retained range. Positions before the stream start
// yield zero, mirroring encoderDict.ByteAt.
func (f *optFinder) byteAt(pos int64) byte {
	if pos < 0 {
		return 0
	}
	return f.dict.buf.data[f.index(pos)]
}

// index maps an absolute stream position to its ring buffer index
// (one modulo). at reads the byte off bytes after a ring index,
// wrapping at most once for the small offsets used here.
func (f *optFinder) index(pos int64) int {
	d := f.dict
	n := len(d.buf.data)
	i := (d.buf.rear + int(pos-d.head)) % n
	if i < 0 {
		i += n
	}
	return i
}

// at reads the byte off bytes after a ring index. Callers keep
// -len(data) < off < len(data), so one conditional wrap suffices.
func (f *optFinder) at(idx, off int) byte {
	data := f.dict.buf.data
	i := idx + off
	if i >= len(data) {
		i -= len(data)
	} else if i < 0 {
		i += len(data)
	}
	return data[i]
}

// adv advances a ring index by k (0 <= k < ring size).
func (f *optFinder) adv(idx, k int) int {
	i := idx + k
	if n := len(f.dict.buf.data); i >= n {
		i -= n
	}
	return i
}

// sub moves a ring index back by d (0 <= d < ring size); used with
// match distances, which are always smaller than the ring.
func (f *optFinder) sub(idx, d int) int {
	i := idx - d
	if i < 0 {
		i += len(f.dict.buf.data)
	}
	return i
}

// matchLen returns the length of the common prefix of the byte
// sequences at absolute positions a and b, capped at limit.
func (f *optFinder) matchLen(a, b int64, limit int) int {
	return f.matchLenIdx(f.index(a), f.index(b), limit)
}

// matchLenIdx is matchLen on precomputed ring indices. It compares
// eight bytes at a time inside each ring segment; results are
// identical to the byte-wise loop.
func (f *optFinder) matchLenIdx(i, j int, limit int) int {
	data := f.dict.buf.data
	n := len(data)
	l := 0
	for l < limit {
		ri, rj := n-i, n-j
		r := ri
		if rj < r {
			r = rj
		}
		if rem := limit - l; r > rem {
			r = rem
		}
		k := 0
		for k+8 <= r {
			x := binary.LittleEndian.Uint64(data[i+k:]) ^
				binary.LittleEndian.Uint64(data[j+k:])
			if x != 0 {
				return l + k + bits.TrailingZeros64(x)/8
			}
			k += 8
		}
		for k < r && data[i+k] == data[j+k] {
			k++
		}
		l += k
		if k < r {
			return l
		}
		i += k
		if i >= n {
			i -= n
		}
		j += k
		if j >= n {
			j -= n
		}
	}
	return l
}

func (f *optFinder) hashAt(pos int64) uint32 {
	return f.hashIdx(f.index(pos))
}

func (f *optFinder) hashIdx(i int) uint32 {
	x := uint32(f.at(i, 0)) |
		uint32(f.at(i, 1))<<8 |
		uint32(f.at(i, 2))<<16 |
		uint32(f.at(i, 3))<<24
	return (x * 0x9E3779B1) >> 16
}

// insertUpTo inserts all positions before upto (as far as four
// bytes are available, i.e. position+4 <= availEnd). Positions are
// inserted in increasing order, so the ring index and the cyclic
// prev slot are tracked incrementally instead of recomputed with
// divisions.
func (f *optFinder) insertUpTo(upto, availEnd int64) {
	n := len(f.dict.buf.data)
	cap64 := int64(f.cap)
	for f.next < upto {
		if f.next+4 > availEnd {
			return
		}
		if !f.idxOK {
			f.nextIdx = f.index(f.next)
			f.nextCyc = f.next % cap64
			f.idxOK = true
		}
		if f.next < 1<<31-1 {
			h := f.hashIdx(f.nextIdx)
			f.prev[f.nextCyc] = f.head[h]
			f.head[h] = int32(f.next)
		}
		f.next++
		f.nextIdx++
		if f.nextIdx >= n {
			f.nextIdx -= n
		}
		f.nextCyc++
		if f.nextCyc >= cap64 {
			f.nextCyc -= cap64
		}
	}
}

// findMatches returns the record-breaking matches at absolute
// position pos (increasing lengths, each with its distance offset)
// and the longest match length, or 0 if there is no match of at
// least two bytes. limit caps the match length considered.
func (f *optFinder) findMatches(pos int64, limit int, out []optMatch) ([]optMatch, int) {
	out = out[:0]
	if limit < 2 || pos < 1 || pos >= 1<<31-1 {
		return out, 0
	}
	availEnd := f.dict.head + int64(f.dict.buf.Buffered())
	if availEnd-pos < 4 {
		return out, 0
	}
	data := f.dict.buf.data
	n := len(data)
	ip := f.index(pos)
	h := f.hashIdx(ip)
	cap64 := int64(f.cap)
	pIdx := pos % cap64
	prev := f.prev
	best := 1
	q := int64(f.head[h])
	for depth := f.depth; q >= 0 && depth > 0; depth-- {
		dist := pos - q
		if dist <= 0 || dist > cap64 {
			break
		}
		// Candidate indices come from ip/pIdx by subtracting the
		// distance (always < ring size), avoiding divisions.
		iq := ip - int(dist)
		if iq < 0 {
			iq += n
		}
		qIdx := pIdx - dist
		if qIdx < 0 {
			qIdx += cap64
		}
		if best < limit {
			ib := ip + best
			if ib >= n {
				ib -= n
			}
			jb := iq + best
			if jb >= n {
				jb -= n
			}
			if data[ib] != data[jb] {
				q = int64(prev[qIdx])
				continue
			}
		}
		l := f.matchLenIdx(ip, iq, limit)
		if l > best {
			best = l
			out = append(out, optMatch{len: uint32(l), dist: uint32(dist - 1)})
			if l >= limit {
				break
			}
		}
		q = int64(prev[qIdx])
	}
	if best < 2 {
		return out[:0], 0
	}
	return out, best
}

// ---------- parser ----------

// optOp is a decided operation awaiting emission. back uses the
// parser's encoding: backLiteral for a literal, 0..3 for a rep
// match (index into the live rep list at emission time), and
// dist+4 for a normal match with distance offset dist.
type optOp struct {
	back uint32
	n    int
	b    byte
}

type optParser struct {
	f       *optFinder
	pricer  optPricer
	opts    []optimal
	pending []optOp
	segs    []optOp

	niceLen uint32

	filled   bool
	lastFill int64

	// scratch state mirroring the C parser's loop variables
	reps       [4]uint32
	curMatches []optMatch
	curLenMain int
}

func newOptParser(f *optFinder, niceLen int) *optParser {
	if niceLen < 2 {
		niceLen = 2
	}
	if niceLen > maxMatchLen {
		niceLen = maxMatchLen
	}
	return &optParser{
		f:       f,
		opts:    make([]optimal, optSlots),
		niceLen: uint32(niceLen),
	}
}

func (o *optParser) emit(op optOp) {
	o.pending = append(o.pending, op)
}

// compress implements the encoder's compression loop in optimal
// mode: it alternates between draining decided operations and
// computing new optimum windows.
func (o *optParser) compress(e *encoder, flags compressFlags) error {
	for {
		for len(o.pending) > 0 {
			op := o.pending[0]
			o.pending = o.pending[1:]
			var operation operation
			switch {
			case op.back == backLiteral:
				operation = lit{op.b}
			case op.back < 4:
				operation = match{distance: int64(e.state.rep[op.back]) + 1, n: op.n}
			default:
				operation = match{distance: int64(op.back-4) + 1, n: op.n}
			}
			// Emit with an explicit rep index: writeOp/writeMatch
			// would re-derive the index from the distance value,
			// which breaks the parser's state model whenever a
			// plain match's distance equals a rep entry.
			var err error
			if e.re.Available() < int64(e.margin) {
				err = ErrLimit
			} else {
				switch x := operation.(type) {
				case lit:
					err = e.writeLiteral(x)
				case match:
					g := 4
					if op.back < 4 {
						g = int(op.back)
					}
					err = e.writeMatchG(x, g)
				}
			}
			if err != nil {
				// Put the op back: emission is resumable.
				o.pending = append([]optOp{op}, o.pending...)
				return err
			}
			e.dict.Discard(operation.Len())
		}
		o.pending = o.pending[:0]
		n := 0
		if flags&all == 0 {
			n = maxMatchLen - 1
		}
		if e.dict.Buffered() <= n {
			return nil
		}
		o.window(e)
	}
}

// extendLenEnd grows the priced range to target, initializing new
// slots as infinite-price literal placeholders (a safe default the
// C code leaves uninitialized; placeholders keep every chain valid).
func (o *optParser) extendLenEnd(cur int, target int) int {
	for cur < target {
		cur++
		slot := &o.opts[cur]
		slot.price = optInfinityPrice
		slot.posPrev = uint32(cur - 1)
		slot.backPrev = backLiteral
		slot.prev1IsLiteral = false
		slot.prev2 = false
	}
	return cur
}

// window computes the optimum path for one window starting at the
// current dictionary head and appends the decided operations to
// o.pending. It always decides at least one operation.
func (o *optParser) window(e *encoder) {
	st := e.state
	f := o.f
	H := e.dict.Pos()
	availTotal := int64(e.dict.Buffered())
	end := H + availTotal

	if !o.filled || H-o.lastFill >= 1024 {
		o.pricer.fill(st)
		o.filled = true
		o.lastFill = H
	}

	// ---- helper1: evaluate the first position ----
	f.insertUpTo(H, end)
	avail0 := availTotal
	if avail0 > maxMatchLen {
		avail0 = maxMatchLen
	}
	matches, lenMain := f.findMatches(H, int(avail0), o.curMatches[:0])
	o.curMatches = matches

	iH := f.index(H)
	var repLens [4]uint32
	repMax := 0
	for i := 0; i < 4; i++ {
		d := int64(st.rep[i]) + 1
		if avail0 >= 2 && H >= d {
			if l := f.matchLenIdx(iH, f.sub(iH, int(d)), int(avail0)); l >= 2 {
				repLens[i] = uint32(l)
			}
		}
		if repLens[i] > repLens[repMax] {
			repMax = i
		}
	}

	nice := o.niceLen
	if repLens[repMax] >= nice {
		o.emit(optOp{back: uint32(repMax), n: int(repLens[repMax])})
		return
	}
	if lenMain >= int(nice) {
		o.emit(optOp{back: matches[len(matches)-1].dist + 4, n: lenMain})
		return
	}

	curByte := f.at(iH, 0)
	matchByte := byte(0)
	if H >= int64(st.rep[0])+1 {
		matchByte = f.at(iH, -int(st.rep[0])-1)
	}
	if lenMain < 2 && curByte != matchByte && repLens[repMax] < 2 {
		o.emit(optOp{back: backLiteral, n: 1, b: curByte})
		return
	}

	opts := o.opts
	opts[0].state = st.state
	opts[0].backs = st.rep
	opts[0].price = 0

	posState := uint32(H) & st.posBitMask
	state2 := (st.state << maxPosBits) | posState

	opts[1].price = bit0Price(st.isMatch[state2]) +
		literalPrice(st, H, f.at(iH, -1), !isLiteralState(st.state),
			matchByte, curByte)
	makeLiteral(&opts[1])

	matchPrice := bit1Price(st.isMatch[state2])
	repMatchPrice := matchPrice + bit1Price(st.isRep[st.state])

	if matchByte == curByte && H >= 1 {
		// Short rep needs one byte of history (H >= 1).
		srp := repMatchPrice + shortRepPrice(st, st.state, posState)
		if srp < opts[1].price {
			opts[1].price = srp
			makeShortRep(&opts[1])
		}
	}

	lenEnd := lenMain
	if int(repLens[repMax]) > lenEnd {
		lenEnd = int(repLens[repMax])
	}
	if lenEnd < 2 {
		o.emit(optOp{back: opts[1].backPrev, n: 1, b: curByte})
		return
	}

	opts[1].posPrev = 0
	for l := 2; l <= lenEnd; l++ {
		slot := &opts[l]
		slot.price = optInfinityPrice
		slot.posPrev = uint32(l - 1)
		slot.backPrev = backLiteral
		slot.prev1IsLiteral = false
		slot.prev2 = false
	}

	for i := 0; i < 4; i++ {
		rl := repLens[i]
		if rl < 2 {
			continue
		}
		price := repMatchPrice + pureRepPrice(st, uint32(i), st.state, posState)
		for l := int(rl); l >= 2; l-- {
			p := price + o.pricer.repLenPrices[posState][l-minMatchLen]
			if p < opts[l].price {
				opts[l].price = p
				opts[l].posPrev = 0
				opts[l].backPrev = uint32(i)
				opts[l].prev1IsLiteral = false
			}
		}
	}

	normalMatchPrice := matchPrice + bit0Price(st.isRep[st.state])
	startLen := 2
	if repLens[0] >= 2 {
		startLen = int(repLens[0]) + 1
	}
	if startLen <= lenMain {
		i := 0
		for int(matches[i].len) < startLen {
			i++
		}
		var parts [4]uint32
		partsDist := ^uint32(0)
		for l := startLen; ; l++ {
			for int(matches[i].len) < l {
				i++
			}
			dist := matches[i].dist
			if dist != partsDist {
				parts = o.pricer.distParts(dist)
				partsDist = dist
			}
			p := normalMatchPrice +
				parts[lenState(uint32(l)-minMatchLen)] +
				o.pricer.lenPrices[posState][l-minMatchLen]
			if p < opts[l].price {
				opts[l].price = p
				opts[l].posPrev = 0
				opts[l].backPrev = dist + 4
				opts[l].prev1IsLiteral = false
			}
			if l == lenMain {
				break
			}
		}
	}

	// ---- main loop over the window ----
	o.reps = st.rep
	cur := 1
	for cur < lenEnd {
		pos := H + int64(cur)
		availFull := availTotal - int64(cur)
		if m := int64(optSlots - 1 - cur); availFull > m {
			availFull = m
		}
		lim := availFull
		if lim > maxMatchLen {
			lim = maxMatchLen
		}
		f.insertUpTo(pos, end)
		o.curMatches, o.curLenMain = f.findMatches(pos, int(lim), o.curMatches[:0])
		if o.curLenMain >= int(nice) {
			break
		}
		lenEnd = o.helper2(e, cur, pos, lenEnd, int(availFull))
		cur++
	}

	o.backward(H, uint32(cur))
}

// backward converts the optimum table ending at slot end into the
// forward sequence of operations and appends them to o.pending.
func (o *optParser) backward(H int64, end uint32) {
	segs := o.segs[:0]
	s := end
	for s != 0 {
		op := &o.opts[s]
		if op.prev1IsLiteral {
			if op.prev2 {
				segs = append(segs, optOp{back: 0, n: int(s - op.posPrev)})
				segs = append(segs, optOp{back: backLiteral, n: 1,
					b: o.f.byteAt(H + int64(op.posPrev) - 1)})
				segs = append(segs, optOp{back: op.backPrev2,
					n: int(op.posPrev - 1 - op.posPrev2),
					b: o.f.byteAt(H + int64(op.posPrev2))})
				s = op.posPrev2
			} else {
				segs = append(segs, optOp{back: 0, n: int(s - op.posPrev)})
				segs = append(segs, optOp{back: backLiteral, n: 1,
					b: o.f.byteAt(H + int64(op.posPrev) - 1)})
				s = op.posPrev - 1
			}
		} else {
			segs = append(segs, optOp{back: op.backPrev,
				n: int(s - op.posPrev),
				b: o.f.byteAt(H + int64(op.posPrev))})
			s = op.posPrev
		}
	}
	for i, j := 0, len(segs)-1; i < j; i, j = i+1, j-1 {
		segs[i], segs[j] = segs[j], segs[i]
	}
	o.pending = append(o.pending, segs...)
	o.segs = segs[:0]
}

// helper2 extends the optimum table at slot cur (absolute position
// pos) and returns the new lenEnd. o.curMatches/o.curLenMain hold
// the match-finder results for pos; o.reps is the shared rep-list
// scratch, kept equal to opts[cur-1].backs on entry.
func (o *optParser) helper2(e *encoder, cur int, pos int64,
	lenEnd int, bufAvailFull int) int {

	st := e.state
	opts := o.opts
	f := o.f

	// Reconstruct state index and rep list for opts[cur].
	posPrev := int(opts[cur].posPrev)
	var stIdx uint32
	if opts[cur].prev1IsLiteral {
		posPrev--
		if opts[cur].prev2 {
			stIdx = opts[opts[cur].posPrev2].state
			if opts[cur].backPrev2 < 4 {
				stIdx = stateAfterRep(stIdx)
			} else {
				stIdx = stateAfterMatch(stIdx)
			}
		} else {
			stIdx = opts[posPrev].state
		}
		stIdx = stateAfterLiteral(stIdx)
	} else {
		stIdx = opts[posPrev].state
	}

	if posPrev == cur-1 {
		// A one-byte step: short rep if backPrev == 0,
		// literal otherwise (backPrev == backLiteral).
		if opts[cur].backPrev == 0 {
			stIdx = stateAfterShortRep(stIdx)
		} else {
			stIdx = stateAfterLiteral(stIdx)
		}
	} else {
		var back uint32
		if opts[cur].prev1IsLiteral && opts[cur].prev2 {
			posPrev = int(opts[cur].posPrev2)
			back = opts[cur].backPrev2
			stIdx = stateAfterRep(stIdx)
		} else {
			back = opts[cur].backPrev
			if back < 4 {
				stIdx = stateAfterRep(stIdx)
			} else {
				stIdx = stateAfterMatch(stIdx)
			}
		}
		reps := &o.reps
		if back < 4 {
			reps[0] = opts[posPrev].backs[back]
			i := 1
			for ; i <= int(back); i++ {
				reps[i] = opts[posPrev].backs[i-1]
			}
			for ; i < 4; i++ {
				reps[i] = opts[posPrev].backs[i]
			}
		} else {
			reps[0] = back - 4
			for i := 1; i < 4; i++ {
				reps[i] = opts[posPrev].backs[i-1]
			}
		}
	}

	opts[cur].state = stIdx
	opts[cur].backs = o.reps

	curPrice := opts[cur].price
	reps := o.reps

	ip := f.index(pos)
	curByte := f.at(ip, 0)
	matchByte := byte(0)
	if pos >= int64(reps[0])+1 {
		matchByte = f.at(ip, -int(reps[0])-1)
	}
	posState := uint32(pos) & st.posBitMask
	state2 := (stIdx << maxPosBits) | posState

	curAnd1Price := curPrice + bit0Price(st.isMatch[state2]) +
		literalPrice(st, pos, f.at(ip, -1), !isLiteralState(stIdx),
			matchByte, curByte)

	nextIsLiteral := false
	if curAnd1Price < opts[cur+1].price {
		opts[cur+1].price = curAnd1Price
		opts[cur+1].posPrev = uint32(cur)
		makeLiteral(&opts[cur+1])
		nextIsLiteral = true
	}

	matchPrice := curPrice + bit1Price(st.isMatch[state2])
	repMatchPrice := matchPrice + bit1Price(st.isRep[stIdx])

	if matchByte == curByte &&
		!(opts[cur+1].posPrev < uint32(cur) && opts[cur+1].backPrev == 0) {
		srp := repMatchPrice + shortRepPrice(st, stIdx, posState)
		if srp <= opts[cur+1].price {
			opts[cur+1].price = srp
			opts[cur+1].posPrev = uint32(cur)
			makeShortRep(&opts[cur+1])
			nextIsLiteral = true
		}
	}

	if bufAvailFull < 2 {
		return lenEnd
	}
	bufAvail := bufAvailFull
	if bufAvail > int(o.niceLen) {
		bufAvail = int(o.niceLen)
	}

	// Trial: literal at cur, then rep0 match.
	if !nextIsLiteral && matchByte != curByte {
		limit := bufAvailFull
		if m := int(o.niceLen) + 1; limit > m {
			limit = m
		}
		lenTest := 0
		if limit > 1 {
			isrc := f.sub(ip, int(reps[0])+1)
			lenTest = f.matchLenIdx(f.adv(ip, 1), f.adv(isrc, 1), limit-1)
		}
		if lenTest >= 2 {
			st2 := stateAfterLiteral(stIdx)
			posStateNext := uint32(pos+1) & st.posBitMask
			nextRepMatchPrice := curAnd1Price +
				bit1Price(st.isMatch[(st2<<maxPosBits)|posStateNext]) +
				bit1Price(st.isRep[st2])
			offset := cur + 1 + lenTest
			lenEnd = o.extendLenEnd(lenEnd, offset)
			p := nextRepMatchPrice +
				pureRepPrice(st, 0, st2, posStateNext) +
				o.pricer.repLenPrices[posStateNext][lenTest-minMatchLen]
			if p < opts[offset].price {
				opts[offset].price = p
				opts[offset].posPrev = uint32(cur + 1)
				opts[offset].backPrev = 0
				opts[offset].prev1IsLiteral = true
				opts[offset].prev2 = false
			}
		}
	}

	startLen := 2

	// Rep matches.
	for repIndex := 0; repIndex < 4; repIndex++ {
		if pos < int64(reps[repIndex])+1 {
			continue
		}
		isrc := f.sub(ip, int(reps[repIndex])+1)
		lenTest := f.matchLenIdx(ip, isrc, bufAvail)
		if lenTest < 2 {
			continue
		}
		lenEnd = o.extendLenEnd(lenEnd, cur+lenTest)

		lenTestTemp := lenTest
		price := repMatchPrice + pureRepPrice(st, uint32(repIndex), stIdx, posState)
		for l := lenTest; l >= 2; l-- {
			p := price + o.pricer.repLenPrices[posState][l-minMatchLen]
			if p < opts[cur+l].price {
				opts[cur+l].price = p
				opts[cur+l].posPrev = uint32(cur)
				opts[cur+l].backPrev = uint32(repIndex)
				opts[cur+l].prev1IsLiteral = false
			}
		}
		lenTest = lenTestTemp

		if repIndex == 0 {
			startLen = lenTest + 1
		}

		// Trial: this rep match, then a literal, then rep0.
		limit := bufAvailFull
		if m := lenTest + 1 + int(o.niceLen); limit > m {
			limit = m
		}
		lenTest2 := 0
		if lenTest+1 < limit {
			lenTest2 = f.matchLenIdx(f.adv(ip, lenTest+1),
				f.adv(isrc, lenTest+1), limit-lenTest-1)
		}
		if lenTest2 >= 2 {
			st2 := stateAfterRep(stIdx)
			posStateNext := uint32(pos+int64(lenTest)) & st.posBitMask
			curAndLenLitPrice := price +
				o.pricer.repLenPrices[posState][lenTest-minMatchLen] +
				bit0Price(st.isMatch[(st2<<maxPosBits)|posStateNext]) +
				literalPrice(st, pos+int64(lenTest),
					f.at(ip, lenTest-1), true,
					f.at(isrc, lenTest),
					f.at(ip, lenTest))
			st2 = stateAfterLiteral(st2)
			posStateNext = uint32(pos+int64(lenTest)+1) & st.posBitMask
			nextRepMatchPrice := curAndLenLitPrice +
				bit1Price(st.isMatch[(st2<<maxPosBits)|posStateNext]) +
				bit1Price(st.isRep[st2])
			offset := cur + lenTest + 1 + lenTest2
			lenEnd = o.extendLenEnd(lenEnd, offset)
			p := nextRepMatchPrice +
				pureRepPrice(st, 0, st2, posStateNext) +
				o.pricer.repLenPrices[posStateNext][lenTest2-minMatchLen]
			if p < opts[offset].price {
				opts[offset].price = p
				opts[offset].posPrev = uint32(cur + lenTest + 1)
				opts[offset].backPrev = 0
				opts[offset].prev1IsLiteral = true
				opts[offset].prev2 = true
				opts[offset].posPrev2 = uint32(cur)
				opts[offset].backPrev2 = uint32(repIndex)
			}
		}
	}

	// Normal matches.
	newLen := o.curLenMain
	matches := o.curMatches
	if newLen > bufAvail {
		newLen = bufAvail
		// Truncate the match list like liblzma does.
		cnt := 0
		for newLen > int(matches[cnt].len) {
			cnt++
		}
		matches[cnt].len = uint32(newLen)
		matches = matches[:cnt+1]
	}

	if newLen >= startLen {
		normalMatchPrice := matchPrice + bit0Price(st.isRep[stIdx])
		lenEnd = o.extendLenEnd(lenEnd, cur+newLen)
		i := 0
		for int(matches[i].len) < startLen {
			i++
		}
		var parts [4]uint32
		partsDist := ^uint32(0)
		for lenTest := startLen; ; lenTest++ {
			for int(matches[i].len) < lenTest {
				i++
			}
			curBack := matches[i].dist
			if curBack != partsDist {
				parts = o.pricer.distParts(curBack)
				partsDist = curBack
			}
			curAndLenPrice := normalMatchPrice +
				parts[lenState(uint32(lenTest)-minMatchLen)] +
				o.pricer.lenPrices[posState][lenTest-minMatchLen]
			if curAndLenPrice < opts[cur+lenTest].price {
				opts[cur+lenTest].price = curAndLenPrice
				opts[cur+lenTest].posPrev = uint32(cur)
				opts[cur+lenTest].backPrev = curBack + 4
				opts[cur+lenTest].prev1IsLiteral = false
			}
			if lenTest == int(matches[i].len) {
				// Trial: this match, then a literal, then rep0.
				isrc := f.sub(ip, int(curBack)+1)
				limit := bufAvailFull
				if m := lenTest + 1 + int(o.niceLen); limit > m {
					limit = m
				}
				lenTest2 := 0
				if lenTest+1 < limit {
					lenTest2 = f.matchLenIdx(f.adv(ip, lenTest+1),
						f.adv(isrc, lenTest+1), limit-lenTest-1)
				}
				if lenTest2 >= 2 {
					st2 := stateAfterMatch(stIdx)
					posStateNext := uint32(pos+int64(lenTest)) & st.posBitMask
					curAndLenLitPrice := curAndLenPrice +
						bit0Price(st.isMatch[(st2<<maxPosBits)|posStateNext]) +
						literalPrice(st, pos+int64(lenTest),
							f.at(ip, lenTest-1), true,
							f.at(isrc, lenTest),
							f.at(ip, lenTest))
					st2 = stateAfterLiteral(st2)
					posStateNext = uint32(pos+int64(lenTest)+1) & st.posBitMask
					nextRepMatchPrice := curAndLenLitPrice +
						bit1Price(st.isMatch[(st2<<maxPosBits)|posStateNext]) +
						bit1Price(st.isRep[st2])
					offset := cur + lenTest + 1 + lenTest2
					lenEnd = o.extendLenEnd(lenEnd, offset)
					p := nextRepMatchPrice +
						pureRepPrice(st, 0, st2, posStateNext) +
						o.pricer.repLenPrices[posStateNext][lenTest2-minMatchLen]
					if p < opts[offset].price {
						opts[offset].price = p
						opts[offset].posPrev = uint32(cur + lenTest + 1)
						opts[offset].backPrev = 0
						opts[offset].prev1IsLiteral = true
						opts[offset].prev2 = true
						opts[offset].posPrev2 = uint32(cur)
						opts[offset].backPrev2 = curBack + 4
					}
				}
				i++
				if i >= len(matches) {
					break
				}
			}
		}
	}

	return lenEnd
}
