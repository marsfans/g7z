package wim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// XPRESS (LZ77+Huffman variant, [MS-XCA]) as used in WIM resources:
// independent 32 KiB chunks, each holding a 256-byte table of 4-bit
// Huffman code lengths for 512 symbols followed by a bitstream.
//
// The bitstream is a sequence of little-endian 16-bit coding units
// with bits ordered high to low (the wimlib bitstream model): the
// decoder keeps a left-justified bit buffer, loads one u16 whenever
// it needs more bits, and reads the extended-length bytes of long
// matches from the input position just past the last loaded unit.
// An encoder must therefore simulate the decoder's loading to know
// where those literal bytes belong in the stream.
//
// The chunk must also be terminated the way strict decoders
// (7-Zip's Decode_WithExceedWrite) require: after the last token
// an end symbol (256) follows, the rest of the stream is zero
// bits, and the stream length equals exactly what the decoder
// loads while decoding (two words preloaded, one more word
// whenever the consumed-bit count since the last load exceeds
// 16), so its input pointer ends precisely at the chunk end.

const (
	xpressSymbols  = 512
	xpressMaxLen   = 15
	xpressMinMatch = 3
)

// ---------- decoder bitstream (wimlib semantics) ----------

type xpBitReader struct {
	data     []byte
	next     int    // offset of the next byte to load
	bitbuf   uint32 // left-justified: the next bit is bit 31
	bitsleft int
}

func (b *xpBitReader) ensure(n int) {
	if b.bitsleft < n {
		if b.next+2 <= len(b.data) {
			word := uint32(binary.LittleEndian.Uint16(b.data[b.next:]))
			b.bitbuf |= word << (16 - b.bitsleft)
			b.next += 2
		}
		b.bitsleft += 16
	}
}

func (b *xpBitReader) pop(n int) uint32 {
	v := b.bitbuf >> (32 - n)
	b.bitbuf <<= n
	b.bitsleft -= n
	return v
}

// readByte reads a literal byte embedded in the bitstream: the byte
// just past the last loaded coding unit.
func (b *xpBitReader) readByte() byte {
	if b.next >= len(b.data) {
		return 0
	}
	v := b.data[b.next]
	b.next++
	return v
}

func (b *xpBitReader) readU16() uint16 {
	if b.next+2 > len(b.data) {
		return 0
	}
	v := binary.LittleEndian.Uint16(b.data[b.next:])
	b.next += 2
	return v
}

// ---------- Huffman ----------

// canonicalCodes assigns canonical codes for the given lengths
// (0 = unused).
func canonicalCodes(lens *[xpressSymbols]byte) ([xpressSymbols]uint32, error) {
	var count [xpressMaxLen + 1]int
	for _, l := range lens {
		if l > xpressMaxLen {
			return [xpressSymbols]uint32{}, fmt.Errorf("xpress: code length %d out of range", l)
		}
		count[l]++
	}
	if count[0] == xpressSymbols {
		return [xpressSymbols]uint32{}, errors.New("xpress: empty Huffman table")
	}
	count[0] = 0 // unused symbols are not codes; keep them out of the recurrence
	kraft := 0
	for l := 1; l <= xpressMaxLen; l++ {
		kraft += count[l] << uint(xpressMaxLen-l)
	}
	if kraft > 1<<xpressMaxLen {
		return [xpressSymbols]uint32{}, errors.New("xpress: over-subscribed Huffman table")
	}
	var next [xpressMaxLen + 1]uint32
	code := uint32(0)
	for l := 1; l <= xpressMaxLen; l++ {
		code = (code + uint32(count[l-1])) << 1
		next[l] = code
	}
	var codes [xpressSymbols]uint32
	for s := 0; s < xpressSymbols; s++ {
		if lens[s] > 0 {
			codes[s] = next[lens[s]]
			next[lens[s]]++
		}
	}
	return codes, nil
}

type huffDecoder struct {
	counts [xpressMaxLen + 1]int
	sorted []uint16 // symbols in canonical order
	offs   [xpressMaxLen + 1]int
}

func newHuffDecoder(lens *[xpressSymbols]byte) (*huffDecoder, error) {
	if _, err := canonicalCodes(lens); err != nil {
		return nil, err
	}
	d := &huffDecoder{}
	for _, l := range lens {
		d.counts[l]++
	}
	pos := 0
	for l := 1; l <= xpressMaxLen; l++ {
		d.offs[l] = pos
		pos += d.counts[l]
	}
	d.sorted = make([]uint16, pos)
	idx := d.offs
	for s := 0; s < xpressSymbols; s++ {
		if lens[s] > 0 {
			d.sorted[idx[lens[s]]] = uint16(s)
			idx[lens[s]]++
		}
	}
	return d, nil
}

func (d *huffDecoder) decode(b *xpBitReader) (uint16, error) {
	b.ensure(xpressMaxLen)
	code := 0
	first := 0
	for l := 1; l <= xpressMaxLen; l++ {
		if b.bitsleft < 1 {
			return 0, errors.New("xpress: unexpected end of chunk")
		}
		code = (code << 1) | int(b.pop(1))
		if code-first < d.counts[l] {
			return d.sorted[d.offs[l]+code-first], nil
		}
		first = (first + d.counts[l]) << 1
	}
	return 0, errors.New("xpress: invalid Huffman code")
}

// limitHuffman computes length-limited (max 15) canonical code
// lengths for the given symbol frequencies via package-merge.
// Symbols with zero frequency get length 0. The resulting code is
// completed with dummy symbols when it would otherwise be
// incomplete, as XPRESS tables must describe a full prefix code.
func limitHuffman(freq *[xpressSymbols]uint32) [xpressSymbols]byte {
	var lens [xpressSymbols]byte
	type symFreq struct {
		sym  int
		freq uint32
	}
	var used []symFreq
	for s := 0; s < xpressSymbols; s++ {
		if freq[s] > 0 {
			used = append(used, symFreq{s, freq[s]})
		}
	}
	if len(used) == 0 {
		return lens
	}
	if len(used) == 1 {
		lens[used[0].sym] = 1
		d := (used[0].sym + 1) % xpressSymbols
		lens[d] = 1
		return lens
	}
	sort.Slice(used, func(i, j int) bool {
		if used[i].freq != used[j].freq {
			return used[i].freq < used[j].freq
		}
		return used[i].sym < used[j].sym
	})
	// Package-merge: after L-1 rounds of packaging pairs and
	// merging with the leaves, a symbol's code length is the
	// number of selected items (first 2n-2) containing it.
	type item struct {
		weight uint64
		syms   []int
	}
	leaves := make([]item, len(used))
	for i, u := range used {
		leaves[i] = item{weight: uint64(u.freq), syms: []int{u.sym}}
	}
	cur := make([]item, len(leaves))
	copy(cur, leaves)
	for round := 1; round < xpressMaxLen; round++ {
		var pkgs []item
		for i := 0; i+1 < len(cur); i += 2 {
			syms := make([]int, 0, len(cur[i].syms)+len(cur[i+1].syms))
			syms = append(syms, cur[i].syms...)
			syms = append(syms, cur[i+1].syms...)
			pkgs = append(pkgs, item{weight: cur[i].weight + cur[i+1].weight, syms: syms})
		}
		merged := make([]item, 0, len(pkgs)+len(leaves))
		i, j := 0, 0
		for i < len(pkgs) && j < len(leaves) {
			if pkgs[i].weight <= leaves[j].weight {
				merged = append(merged, pkgs[i])
				i++
			} else {
				merged = append(merged, leaves[j])
				j++
			}
		}
		merged = append(merged, pkgs[i:]...)
		merged = append(merged, leaves[j:]...)
		cur = merged
	}
	take := 2*len(used) - 2
	if take > len(cur) {
		take = len(cur)
	}
	for _, it := range cur[:take] {
		for _, s := range it.syms {
			lens[s]++
		}
	}
	// Complete the code with dummy symbols if it is incomplete.
	kraft := 0
	for _, l := range lens {
		if l > 0 {
			kraft += 1 << uint(xpressMaxLen-l)
		}
	}
	deficit := (1 << xpressMaxLen) - kraft
	for s := 0; deficit > 0 && s < xpressSymbols; s++ {
		if lens[s] != 0 {
			continue
		}
		for l := xpressMaxLen; l >= 1; l-- {
			if 1<<uint(xpressMaxLen-l) <= deficit {
				lens[s] = byte(l)
				deficit -= 1 << uint(xpressMaxLen-l)
				break
			}
		}
	}
	return lens
}

// ---------- chunk decompression ----------

// xpressDecompressChunk decompresses one XPRESS chunk.
func xpressDecompressChunk(src []byte, uncompressedSize int) ([]byte, error) {
	if len(src) < xpressSymbols/2 {
		return nil, errors.New("xpress: chunk too short for Huffman table")
	}
	var lens [xpressSymbols]byte
	for i := 0; i < xpressSymbols/2; i++ {
		lens[2*i] = src[i] & 0xF
		lens[2*i+1] = src[i] >> 4
	}
	dec, err := newHuffDecoder(&lens)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, uncompressedSize)
	br := &xpBitReader{data: src[xpressSymbols/2:]}
	for len(out) < uncompressedSize {
		sym, err := dec.decode(br)
		if err != nil {
			return nil, err
		}
		if sym < 256 {
			out = append(out, byte(sym))
			continue
		}
		v := int(sym) - 256
		lenSlot := v & 0xF
		posSlot := v >> 4
		br.ensure(16)
		dist := (1 << uint(posSlot)) + int(br.pop(posSlot))
		length := lenSlot
		if lenSlot == 0xF {
			length += int(br.readByte())
			if length == 0xF+0xFF {
				length = int(br.readU16())
			}
		}
		length += xpressMinMatch
		if dist < 1 || dist > len(out) {
			return nil, fmt.Errorf("xpress: match distance %d out of range at %d", dist, len(out))
		}
		for i := 0; i < length; i++ {
			out = append(out, out[len(out)-dist])
		}
	}
	if len(out) != uncompressedSize {
		return nil, fmt.Errorf("xpress: chunk produced %d bytes, want %d", len(out), uncompressedSize)
	}
	return out, nil
}

// ---------- chunk compression ----------

type xpressToken struct {
	lit  byte // valid when dist == 0
	len  int  // match length (0 for literals)
	dist int
}

// xpressTokenize splits data into literals and matches (greedy with
// one step of lazy evaluation, hash chains over 3-byte prefixes).
func xpressTokenize(data []byte) []xpressToken {
	const hashBits = 13
	const maxChain = 32
	head := make([]int32, 1<<hashBits)
	for i := range head {
		head[i] = -1
	}
	prev := make([]int32, len(data))
	hash := func(i int) uint32 {
		v := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16
		return (v * 0x9E3779B1) >> (32 - hashBits)
	}
	matchAt := func(i int) (bestLen, bestDist int) {
		if i+3 > len(data) {
			return 0, 0
		}
		maxLen := len(data) - i
		if maxLen > 65535+xpressMinMatch {
			maxLen = 65535 + xpressMinMatch
		}
		cand := head[hash(i)]
		for n := 0; cand >= 0 && n < maxChain; n++ {
			d := i - int(cand)
			if d > 32768 {
				break
			}
			l := 0
			for l < maxLen && data[int(cand)+l] == data[i+l] {
				l++
			}
			if l >= xpressMinMatch && l > bestLen {
				bestLen, bestDist = l, d
				if l >= maxLen {
					break
				}
			}
			cand = prev[cand]
		}
		return
	}
	insert := func(i int) {
		if i+3 <= len(data) {
			h := hash(i)
			prev[i] = head[h]
			head[h] = int32(i)
		}
	}
	var toks []xpressToken
	i := 0
	for i < len(data) {
		l, d := matchAt(i)
		if l >= xpressMinMatch {
			if i+1 < len(data) {
				insert(i)
				l2, d2 := matchAt(i + 1)
				if l2 > l {
					toks = append(toks, xpressToken{lit: data[i]})
					i++
					l, d = l2, d2
					toks = append(toks, xpressToken{len: l, dist: d})
					end := i + l
					for ; i < end; i++ {
						insert(i)
					}
					continue
				}
			}
			toks = append(toks, xpressToken{len: l, dist: d})
			end := i + l
			for ; i < end; i++ {
				insert(i)
			}
			continue
		}
		toks = append(toks, xpressToken{lit: data[i]})
		insert(i)
		i++
	}
	return toks
}

// matchParts splits a match into its symbol, position slot and
// extended-length bytes (nil when the length fits the slot).
func matchParts(t xpressToken) (sym uint16, posSlot int, extra []byte) {
	posSlot = 0
	for (1 << uint(posSlot+1)) <= t.dist {
		posSlot++
	}
	l := t.len - xpressMinMatch
	lenSlot := l
	if lenSlot > 0xF {
		lenSlot = 0xF
	}
	sym = uint16(256 + (posSlot << 4) + lenSlot)
	if lenSlot == 0xF {
		if l-0xF < 0xFF {
			extra = []byte{byte(l - 0xF)}
		} else {
			extra = []byte{0xFF, byte(l), byte(l >> 8)}
		}
	}
	return
}

// xpressCompressChunk compresses one chunk. The caller stores the
// chunk raw when the result is not smaller than the input.
func xpressCompressChunk(data []byte) ([]byte, error) {
	toks := xpressTokenize(data)
	var freq [xpressSymbols]uint32
	for _, t := range toks {
		if t.dist == 0 {
			freq[t.lit]++
		} else {
			s, _, _ := matchParts(t)
			freq[s]++
		}
	}
	freq[256]++ // the end-of-chunk marker symbol needs a code too
	lens := limitHuffman(&freq)
	codes, err := canonicalCodes(&lens)
	if err != nil {
		return nil, err
	}

	// Emit the logical bitstream (MSB-first into u16 units) and,
	// in parallel, simulate the decoder's loading to find where
	// each match's extended-length bytes land in the final chunk.
	type insertion struct {
		off  int // byte offset in the final bit region
		data []byte
	}
	var insertions []insertion
	var bits []byte // logical bit region (u16 units)
	var acc uint64  // pending bits, left-justified
	var nacc int
	writeBits := func(v uint32, k int) {
		if k == 0 {
			return
		}
		v &= (1 << uint(k)) - 1
		acc |= uint64(v) << (64 - nacc - k)
		nacc += k
		for nacc >= 16 {
			var w [2]byte
			binary.LittleEndian.PutUint16(w[:], uint16(acc>>48))
			bits = append(bits, w[:]...)
			acc <<= 16
			nacc -= 16
		}
	}
	// Decoder simulation state. The number of bits the decoder
	// has loaded is (decNext - decInserted) * 8: decNext counts
	// final-file bytes, decInserted the literal bytes among them.
	decNext := 0     // decoder's input offset (bytes, final-file coordinates)
	decConsumed := 0 // logical bits consumed
	decInserted := 0 // literal bytes inserted so far
	decEnsure := func(k int) {
		if (decNext-decInserted)*8-decConsumed < k {
			decNext += 2
		}
	}
	decPop := func(k int) { decConsumed += k }

	// 7-Zip decoder simulation: it preloads two words, reloads
	// one word whenever its consumed-bit counter passes 16, and
	// finally demands that the input be consumed exactly and the
	// remaining buffered bits be zero. Count its loads to size
	// the bit region (see the package comment).
	zBitPos := 0
	zLoads := 0
	zConsume := func(k int) {
		zBitPos += k
		if zBitPos > 16 {
			zLoads++
			zBitPos -= 16
		}
	}

	for _, t := range toks {
		if t.dist == 0 {
			decEnsure(xpressMaxLen)
			decPop(int(lens[t.lit]))
			writeBits(codes[t.lit], int(lens[t.lit]))
			zConsume(int(lens[t.lit]))
			continue
		}
		s, posSlot, extra := matchParts(t)
		decEnsure(xpressMaxLen)
		decPop(int(lens[s]))
		writeBits(codes[s], int(lens[s]))
		zConsume(int(lens[s]))
		decEnsure(16)
		decPop(posSlot)
		writeBits(uint32(t.dist-(1<<uint(posSlot))), posSlot)
		zConsume(posSlot)
		if extra != nil {
			insertions = append(insertions, insertion{off: decNext, data: extra})
			decNext += len(extra)
			decInserted += len(extra)
		}
	}
	// End-of-chunk marker symbol, then zero padding sized so the
	// strict decoder consumes the stream exactly.
	writeBits(codes[256], int(lens[256]))
	zConsume(int(lens[256]))
	if nacc > 0 {
		var w [2]byte
		binary.LittleEndian.PutUint16(w[:], uint16(acc>>48))
		bits = append(bits, w[:]...)
	}
	if need := 4 + 2*zLoads; len(bits) < need {
		bits = append(bits, make([]byte, need-len(bits))...)
	}

	// Splice the literal bytes into the bit region at the offsets
	// the simulation produced.
	region := make([]byte, 0, len(bits)+8)
	wpos := 0 // read position in bits
	done := 0 // literal bytes inserted so far
	for _, ins := range insertions {
		target := ins.off - done // position within the pure bit region
		if target > len(bits) {
			bits = append(bits, make([]byte, target-len(bits))...)
		}
		region = append(region, bits[wpos:target]...)
		region = append(region, ins.data...)
		wpos = target
		done += len(ins.data)
	}
	region = append(region, bits[wpos:]...)

	out := make([]byte, 0, xpressSymbols/2+len(region))
	for i := 0; i < xpressSymbols/2; i++ {
		out = append(out, lens[2*i]|(lens[2*i+1]<<4))
	}
	return append(out, region...), nil
}
