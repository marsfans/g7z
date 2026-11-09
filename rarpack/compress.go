package rarpack

// RAR5 (algorithm version 0) compressor core.
// Design notes (all constants cross-checked against UnRAR source):
//   - Only literal (0-255) and new-match (>=262) main symbols are emitted.
//     Repeat/old-distance/filter symbols are optional and never produced.
//   - No filters are applied (filters are an encoder choice in RAR5).
//   - Bit stream is MSB-first, matching BitInput::getbits().

const (
	ncSize   = 306                                // LD alphabet: 256 literals + filter/rep slots + 44 length slots
	dcSize   = 64                                 // DD distance slots (base set, dict <= 4 GB)
	ldcSize  = 16                                 // LDD low-distance values
	rcSize   = 44                                 // RD repeat-distance lengths (unused, all zero lengths)
	bcSize   = 20                                 // BD pre-code alphabet
	tableLen = ncSize + dcSize + ldcSize + rcSize // 430 lengths per block table

	maxMatch   = 4097 // MAX_LZ_MATCH (0x1001)
	blockData  = 512 * 1024
	dictSize   = 1 << 24 // 16 MB window; header dict field N=7
	dictFieldN = 7
)

// ---------- bit writer (MSB first) ----------

type bitWriter struct {
	buf   []byte
	acc   uint64
	nacc  int // bits held in acc
	total int // total bits written
}

func (w *bitWriter) writeBits(val uint32, n int) {
	if n == 0 {
		return
	}
	w.acc = (w.acc << uint(n)) | uint64(val)&((1<<uint(n))-1)
	w.nacc += n
	w.total += n
	for w.nacc >= 8 {
		shift := uint(w.nacc - 8)
		w.buf = append(w.buf, byte(w.acc>>shift))
		w.acc &= (1 << shift) - 1
		w.nacc -= 8
	}
}

func (w *bitWriter) finish() ([]byte, int) {
	bitsUsed := w.total % 8
	if w.nacc > 0 {
		w.buf = append(w.buf, byte(w.acc<<uint(8-w.nacc)))
		w.acc = 0
		w.nacc = 0
	}
	if bitsUsed == 0 {
		bitsUsed = 8
	}
	return w.buf, bitsUsed
}

// ---------- LZ tokens ----------

type token struct {
	filter bool // RAR5 filter definition (MainSlot 256)
	fstart int  // filter block start, relative to current stream position
	flen   int  // filter block length
	match  bool
	rep    int // -1 = new match; 0..3 = repeat OldDist[rep]; 4 = repeat last (slot 257)
	lit    byte
	// match fields (actual values)
	length int
	dist   int
	// precomputed encoding
	lenSlot  int
	lenExtra uint32
	lenBits  int
	distSlot int
	dBits    int
	distHi   uint32 // high extra bits (dBits>4), count = dBits-4
	needLDD  bool
	lddVal   int
	distLo   uint32 // extra bits when 1<=dBits<=3
}

// encodeLength maps an encoded length value (2..4097) to slot+extra bits.
// Decoder: SlotToLength(slot): base 2; slot<8 -> +slot; else
// LBits=slot/4-1 and value += (4|(slot&3))<<LBits + extra(LBits bits).
func encodeLength(encLen int) (slot int, extra uint32, bits int) {
	v := encLen - 2 // 0..4095
	if v < 8 {
		return v, 0, 0
	}
	lb := 0
	for (4 << uint(lb+1)) <= v {
		lb++
	}
	// lb = bitlen(v)-3
	slot = 4*(lb+1) + ((v >> uint(lb)) & 3)
	extra = uint32(v) & ((1 << uint(lb)) - 1)
	return slot, extra, lb
}

// encodeDistance maps an actual distance (1..dictSize) into RAR5 slots.
// Decoder works on Distance starting at 1:
//
//	slot<4: Distance = 1+slot
//	else: DBits=slot/2-1; Distance = 1+(2|(slot&1))<<DBits + rem
//	rem: DBits 1..3 -> DBits plain bits; DBits>=4 -> high bits <<4 + LDD sym.
func encodeDistance(dist int) (slot, dBits int, hi uint32, needLDD bool, ldd int, lo uint32) {
	t := dist - 1
	if t < 4 {
		return t, 0, 0, false, 0, 0
	}
	// d = floor(log2(t)) - 1
	d := 0
	for (1 << uint(d+2)) <= t {
		d++
	}
	base := 2 << uint(d)
	slot = 2*d + 2
	if t >= 3<<uint(d) {
		base = 3 << uint(d)
		slot++
	}
	rem := t - base
	switch {
	case d >= 4:
		return slot, d, uint32(rem >> 4), true, rem & 15, 0
	default:
		return slot, d, 0, false, 0, uint32(rem)
	}
}

func lenIncrement(dist int) int {
	inc := 0
	if dist > 0x100 {
		inc++
	}
	if dist > 0x2000 {
		inc++
	}
	if dist > 0x40000 {
		inc++
	}
	return inc
}

// ---------- matcher ----------

const hashBits = 17

type matcher struct {
	data []byte
	head []int32
	prev []int32
	done []bool
}

func hash4(data []byte, pos int) uint32 {
	v := uint32(data[pos]) | uint32(data[pos+1])<<8 | uint32(data[pos+2])<<16 | uint32(data[pos+3])<<24
	return (v * 2654435761) >> (32 - hashBits)
}

func newMatcher(data []byte) *matcher {
	m := &matcher{data: data, head: make([]int32, 1<<hashBits), prev: make([]int32, len(data)), done: make([]bool, len(data))}
	for i := range m.head {
		m.head[i] = -1
	}
	return m
}

func (m *matcher) insert(pos int) {
	if pos+4 > len(m.data) || m.done[pos] {
		return
	}
	m.done[pos] = true
	h := hash4(m.data, pos)
	m.prev[pos] = m.head[h]
	m.head[h] = int32(pos)
}

func (m *matcher) findMatch(pos int, maxLen int) (bestLen, bestDist int) {
	if pos+4 > len(m.data) {
		return 0, 0
	}
	cand := m.head[hash4(m.data, pos)]
	tries := 0
	limit := maxLen
	if pos+limit > len(m.data) {
		limit = len(m.data) - pos
	}
	for cand >= 0 && tries < 384 {
		d := pos - int(cand)
		if d > dictSize {
			break // chain is newest-first: distances only grow
		}
		// quick reject on the byte at current best length
		if bestLen == 0 || (bestLen < limit && m.data[int(cand)+bestLen] == m.data[pos+bestLen]) {
			l := 0
			for l < limit && m.data[int(cand)+l] == m.data[pos+l] {
				l++
			}
			if l > bestLen && l >= 4 {
				// distance-dependent minimum encoded length
				if l-lenIncrement(d) >= 2 {
					bestLen, bestDist = l, d
					if l >= limit {
						break
					}
				}
			}
		}
		cand = m.prev[cand]
		tries++
	}
	return bestLen, bestDist
}

func tokenizeBlock(m *matcher, st *streamState, start, end int) []token {
	var toks []token
	pos := start
	// Positions < pos were inserted while processing earlier blocks.
	for pos < end {
		maxLen := end - pos
		if maxLen > maxMatch {
			maxLen = maxMatch
		}
		l, d := m.findMatch(pos, maxLen)
		if l >= 4 && pos+1 < end {
			// Lazy evaluation: one literal, then a strictly longer match.
			m.insert(pos)
			maxLen2 := end - (pos + 1)
			if maxLen2 > maxMatch {
				maxLen2 = maxMatch
			}
			if l2, d2 := m.findMatch(pos+1, maxLen2); l2 > l {
				toks = append(toks, token{lit: m.data[pos]})
				pos++
				emitMatch(st, &toks, l2, d2)
				for p := pos; p < pos+l2; p++ {
					m.insert(p)
				}
				pos += l2
				continue
			}
		}
		if l >= 4 {
			emitMatch(st, &toks, l, d)
			for p := pos; p < pos+l; p++ {
				m.insert(p)
			}
			pos += l
			continue
		}
		toks = append(toks, token{lit: m.data[pos]})
		m.insert(pos)
		pos++
	}
	return toks
}

// streamState mirrors the decoder's OldDist ring and LastLength.
type streamState struct {
	oldDist    [4]int // 0 = invalid sentinel (real distances are >= 1)
	lastLength int
}

func (st *streamState) insertDist(d int) {
	st.oldDist[3] = st.oldDist[2]
	st.oldDist[2] = st.oldDist[1]
	st.oldDist[1] = st.oldDist[0]
	st.oldDist[0] = d
}

// chooseRep returns a rep code if dist is in OldDist: 4 for slot 257
// (same dist as OldDist[0] and same length as LastLength), else 0..3,
// else -1. It does not mutate state.
func (st *streamState) chooseRep(length, dist int) int {
	if dist == st.oldDist[0] && length == st.lastLength && st.lastLength != 0 {
		return 4
	}
	for k := 0; k < 4; k++ {
		if st.oldDist[k] == dist {
			return k
		}
	}
	return -1
}

// applyRep updates state after emitting a rep token (decoder semantics).
func (st *streamState) applyRep(rep, length int) {
	if rep >= 0 && rep < 4 {
		d := st.oldDist[rep]
		for i := rep; i > 0; i-- {
			st.oldDist[i] = st.oldDist[i-1]
		}
		st.oldDist[0] = d
		st.lastLength = length
	}
	// rep == 4 (slot 257): OldDist and LastLength unchanged.
}

func emitMatch(st *streamState, toks *[]token, length, dist int) {
	if rep := st.chooseRep(length, dist); rep >= 0 {
		// Repeat-distance encoding: length goes through the RD table
		// with NO distance-dependent increment (decoder semantics).
		slot, extra, bits := encodeLength(length)
		*toks = append(*toks, token{match: true, rep: rep, length: length, dist: dist,
			lenSlot: slot, lenExtra: extra, lenBits: bits})
		st.applyRep(rep, length)
		return
	}
	encLen := length - lenIncrement(dist)
	slot, extra, bits := encodeLength(encLen)
	t := token{match: true, rep: -1, length: length, dist: dist, lenSlot: slot, lenExtra: extra, lenBits: bits}
	t.distSlot, t.dBits, t.distHi, t.needLDD, t.lddVal, t.distLo = encodeDistance(dist)
	*toks = append(*toks, t)
	st.insertDist(dist)
	st.lastLength = length
}

// writeFilterData encodes a value the way ReadFilterData reads it:
// 2 bits (byte count-1), then that many bytes little-endian.
func writeFilterData(w *bitWriter, v int) {
	byteCount := 1
	for x := v; x > 0xff; x >>= 8 {
		byteCount++
	}
	w.writeBits(uint32(byteCount-1), 2)
	for i := 0; i < byteCount; i++ {
		w.writeBits(uint32((v>>(8*i))&0xff), 8)
	}
}

// ---------- block encoding ----------

func encodeBlock(toks []token, last bool) []byte {
	// Frequencies.
	ldFreq := make([]uint32, ncSize)
	ddFreq := make([]uint32, dcSize)
	lddFreq := make([]uint32, ldcSize)
	rdFreq := make([]uint32, rcSize)
	for _, t := range toks {
		if t.filter {
			ldFreq[256]++
		} else if !t.match {
			ldFreq[t.lit]++
		} else if t.rep == 4 {
			ldFreq[257]++
		} else if t.rep >= 0 {
			ldFreq[258+t.rep]++
			rdFreq[t.lenSlot]++
		} else {
			ldFreq[262+t.lenSlot]++
			ddFreq[t.distSlot]++
			if t.needLDD {
				lddFreq[t.lddVal]++
			}
		}
	}
	ldLen := buildLengths(ldFreq, 15)
	ddLen := buildLengths(ddFreq, 15)
	lddLen := buildLengths(lddFreq, 15)
	rdLen := buildLengths(rdFreq, 15)

	// Combined table of 430 lengths in decoder order: LD, DD, LDD, RD.
	table := make([]int, 0, tableLen)
	table = append(table, ldLen...)
	table = append(table, ddLen...)
	table = append(table, lddLen...)
	table = append(table, rdLen...)

	// BD pre-code: histogram of the 430 length values (symbols 0..15).
	bdFreq := make([]uint32, bcSize)
	for _, l := range table {
		bdFreq[l]++
	}
	bdLen := buildLengths(bdFreq, 14)
	bdCodes := canonicalCodes(bdLen)
	ldCodes := canonicalCodes(ldLen)
	ddCodes := canonicalCodes(ddLen)
	lddCodes := canonicalCodes(lddLen)
	rdCodes := canonicalCodes(rdLen)

	w := &bitWriter{}
	// BD lengths: 20 nibbles, values <=14 so no 15-escape is triggered.
	for i := 0; i < bcSize; i++ {
		w.writeBits(uint32(bdLen[i]), 4)
	}
	// The 430 table lengths as BD-coded symbols (literal lengths only).
	for _, l := range table {
		w.writeBits(bdCodes[l], bdLen[l])
	}
	// Tokens.
	for _, t := range toks {
		if t.filter {
			w.writeBits(ldCodes[256], ldLen[256])
			writeFilterData(w, t.fstart)
			writeFilterData(w, t.flen)
			w.writeBits(filterTypeE8E9, 3)
			continue
		}
		if !t.match {
			w.writeBits(ldCodes[t.lit], ldLen[t.lit])
			continue
		}
		if t.rep == 4 {
			w.writeBits(ldCodes[257], ldLen[257])
			continue
		}
		if t.rep >= 0 {
			ms := 258 + t.rep
			w.writeBits(ldCodes[ms], ldLen[ms])
			w.writeBits(rdCodes[t.lenSlot], rdLen[t.lenSlot])
			if t.lenBits > 0 {
				w.writeBits(t.lenExtra, t.lenBits)
			}
			continue
		}
		ms := 262 + t.lenSlot
		w.writeBits(ldCodes[ms], ldLen[ms])
		if t.lenBits > 0 {
			w.writeBits(t.lenExtra, t.lenBits)
		}
		w.writeBits(ddCodes[t.distSlot], ddLen[t.distSlot])
		switch {
		case t.dBits >= 4:
			if t.dBits > 4 {
				w.writeBits(t.distHi, t.dBits-4)
			}
			w.writeBits(lddCodes[t.lddVal], lddLen[t.lddVal])
		case t.dBits > 0:
			w.writeBits(t.distLo, t.dBits)
		}
	}
	data, bitSize := w.finish()

	// Block header: flags, checksum, size (1-3 bytes LE).
	size := len(data)
	byteCount := 1
	if size > 0xffff {
		byteCount = 3
	} else if size > 0xff {
		byteCount = 2
	}
	flags := 0x80 | (byteCount-1)<<3 | (bitSize - 1)
	if last {
		flags |= 0x40
	}
	check := byte(0x5a ^ flags ^ size ^ (size >> 8) ^ (size >> 16))
	out := make([]byte, 0, size+2+byteCount)
	out = append(out, byte(flags), check)
	for i := 0; i < byteCount; i++ {
		out = append(out, byte(size>>(8*i)))
	}
	out = append(out, data...)
	return out
}

// compressRange compresses m.data[start:end] into RAR5 blocks using the
// shared matcher and stream state (shared across files in solid mode).
// If useFilter is set, an E8E9 filter definition token is prepended to
// the first block; m.data must then hold the *transformed* bytes.
func compressRange(m *matcher, st *streamState, start, end int, useFilter bool) []byte {
	var out []byte
	for bs := start; bs < end; bs += blockData {
		be := bs + blockData
		if be > end {
			be = end
		}
		toks := tokenizeBlock(m, st, bs, be)
		if useFilter && bs == start {
			var ftoks []token
			for _, ch := range filterChunks(end - start) {
				ftoks = append(ftoks, token{filter: true, fstart: ch[0], flen: ch[1]})
			}
			toks = append(ftoks, toks...)
		}
		out = append(out, encodeBlock(toks, be == end)...)
	}
	return out
}

// compressFiltered compresses E8E9-transformed data with a filter token.
func compressFiltered(transformed []byte) []byte {
	if len(transformed) == 0 {
		return nil
	}
	m := newMatcher(transformed)
	st := &streamState{}
	out := compressRange(m, st, 0, len(transformed), true)
	if len(out) >= len(transformed) {
		return nil
	}
	return out
}

// compressData compresses one file's data (non-solid). Returns nil if the
// result is not smaller than the input.
func compressData(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	m := newMatcher(data)
	st := &streamState{}
	out := compressRange(m, st, 0, len(data), false)
	if len(out) >= len(data) {
		return nil
	}
	return out
}
