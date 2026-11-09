package rarpack

import (
	"container/heap"
)

// Length-limited canonical Huffman code construction.
// Strategy: plain Huffman over adaptively smoothed frequencies. Smoothing
// (adding total/div to every used symbol) bounds the max/min frequency
// ratio, which bounds tree depth; we try progressively stronger smoothing
// until the depth fits maxLen. Plain Huffman lengths always form a
// complete prefix code, so no fragile Kraft repair is needed.
func buildLengths(freq []uint32, maxLen int) []int {
	n := len(freq)
	lengths := make([]int, n)
	used := []int{}
	var total uint64
	for i, f := range freq {
		if f > 0 {
			used = append(used, i)
			total += uint64(f)
		}
	}
	if len(used) == 0 {
		return lengths
	}
	if len(used) == 1 {
		// Single symbol: give it length 1 plus a dummy partner so the
		// canonical code is well formed. Dummy is never emitted.
		lengths[used[0]] = 1
		for i := 0; i < n; i++ {
			if freq[i] == 0 {
				lengths[i] = 1
				break
			}
		}
		return lengths
	}
	for _, div := range []uint64{0, 4096, 1024, 256, 64, 16, 4, 1} {
		smoothed := make([]uint64, n)
		var add uint64
		if div != 0 {
			add = total / div
		}
		for _, i := range used {
			smoothed[i] = uint64(freq[i]) + add
		}
		depth := huffmanDepths(smoothed)
		md := 0
		for _, d := range depth {
			if d > md {
				md = d
			}
		}
		if md <= maxLen {
			copy(lengths, depth)
			return lengths
		}
	}
	copy(lengths, huffmanDepths(freq64Of(freq))) // unreachable in practice
	return lengths
}

func freq64Of(freq []uint32) []uint64 {
	out := make([]uint64, len(freq))
	for i, f := range freq {
		out[i] = uint64(f)
	}
	return out
}

type huffNode struct {
	freq  uint64
	depth int // max depth of subtree, tie-breaker
	leaf  int // symbol or -1
	left  *huffNode
	right *huffNode
}

type nodeHeap []*huffNode

func (h nodeHeap) Len() int { return len(h) }
func (h nodeHeap) Less(a, b int) bool {
	if h[a].freq != h[b].freq {
		return h[a].freq < h[b].freq
	}
	return h[a].depth < h[b].depth
}
func (h nodeHeap) Swap(a, b int)       { h[a], h[b] = h[b], h[a] }
func (h *nodeHeap) Push(x interface{}) { *h = append(*h, x.(*huffNode)) }
func (h *nodeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

func huffmanDepths(freq []uint64) []int {
	depths := make([]int, len(freq))
	h := &nodeHeap{}
	for i, f := range freq {
		if f > 0 {
			heap.Push(h, &huffNode{freq: f, leaf: i})
		}
	}
	for h.Len() > 1 {
		a := heap.Pop(h).(*huffNode)
		b := heap.Pop(h).(*huffNode)
		d := a.depth
		if b.depth > d {
			d = b.depth
		}
		heap.Push(h, &huffNode{freq: a.freq + b.freq, depth: d + 1, leaf: -1, left: a, right: b})
	}
	root := heap.Pop(h).(*huffNode)
	var walk func(nd *huffNode, d int)
	walk = func(nd *huffNode, d int) {
		if nd.leaf >= 0 {
			if d == 0 {
				d = 1
			}
			depths[nd.leaf] = d
			return
		}
		walk(nd.left, d+1)
		walk(nd.right, d+1)
	}
	walk(root, 0)
	return depths
}

// canonicalCodes assigns canonical prefix codes exactly the way RAR's
// MakeDecodeTables expects: increasing length, symbol index order within
// a length, sequential code values.
func canonicalCodes(lengths []int) []uint32 {
	maxLen := 0
	for _, l := range lengths {
		if l > maxLen {
			maxLen = l
		}
	}
	next := make([]uint32, maxLen+2)
	code := uint32(0)
	for l := 1; l <= maxLen; l++ {
		next[l] = code
		cnt := 0
		for _, s := range lengths {
			if s == l {
				cnt++
			}
		}
		code = (code + uint32(cnt)) << 1
	}
	codes := make([]uint32, len(lengths))
	cur := append([]uint32{}, next...)
	for i, l := range lengths {
		if l > 0 {
			codes[i] = cur[l]
			cur[l]++
		}
	}
	return codes
}

// kraftOK reports whether lengths form a complete prefix code (or empty).
func kraftOK(lengths []int, maxLen int) bool {
	sum := 0
	used := 0
	for _, l := range lengths {
		if l > 0 {
			used++
			sum += 1 << (maxLen - l)
		}
	}
	if used == 0 {
		return true
	}
	return sum == 1<<maxLen
}
