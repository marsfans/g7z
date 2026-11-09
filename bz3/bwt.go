package bz3

// Burrows-Wheeler transform, following the libsais convention used by
// the reference implementation: the transform is computed on the string
// extended with a unique sentinel smaller than every byte. The stored
// form is the last column of the sorted (n+1)x(n+1) rotation matrix with
// the sentinel removed, plus the row index of the original string.

// bwtForward computes the stored BWT form of data: the last column of
// the sorted rotations of data+sentinel, with the sentinel removed,
// and the row index of the original string.
func bwtForward(data []byte) ([]byte, int) {
	n := len(data)
	if n == 0 {
		return nil, 0
	}
	sa := suffixArray(data)
	idx := -1
	L := make([]byte, 0, n)
	for i, s := range sa {
		if s == 0 {
			idx = i
			continue
		}
		L = append(L, data[s-1])
	}
	return L, idx
}

// suffixArray returns the suffix array of data extended with a unique
// sentinel smaller than any byte (conceptually at position len(data)).
// It uses prefix doubling with radix (counting) sort: O(n log n).
func suffixArray(data []byte) []int32 {
	n := len(data)
	m := n + 1
	sa := make([]int32, m)
	rank := make([]int32, m)
	for i := 0; i < n; i++ {
		rank[i] = int32(data[i]) + 1 // 1..256
		sa[i] = int32(i)
	}
	rank[n] = 0 // sentinel
	sa[n] = int32(n)

	sa2 := make([]int32, m)
	tmp := make([]int32, m)
	rank2 := func(i int32, k int) int32 {
		if int(i)+k < m {
			return rank[i+int32(k)]
		}
		return -1
	}
	countingSort := func(k int) {
		// Sort by second key, then first key (radix). Keys are shifted
		// by +1 so that -1 (past the end) sorts first.
		maxRank := int32(0)
		for i := 0; i < m; i++ {
			if rank[i] > maxRank {
				maxRank = rank[i]
			}
		}
		cnt := make([]int32, maxRank+2)
		// second key
		for i := 0; i < m; i++ {
			cnt[rank2(sa[i], k)+1]++
		}
		sum := int32(0)
		for i := range cnt {
			cnt[i], sum = sum, sum+cnt[i]
		}
		for i := 0; i < m; i++ {
			s := sa[i]
			key := rank2(s, k) + 1
			sa2[cnt[key]] = s
			cnt[key]++
		}
		// first key
		for i := range cnt {
			cnt[i] = 0
		}
		for i := 0; i < m; i++ {
			cnt[rank[sa2[i]]+1]++
		}
		sum = 0
		for i := range cnt {
			cnt[i], sum = sum, sum+cnt[i]
		}
		for i := 0; i < m; i++ {
			s := sa2[i]
			key := rank[s] + 1
			sa[cnt[key]] = s
			cnt[key]++
		}
	}

	for k := 1; ; k <<= 1 {
		countingSort(k)
		tmp[sa[0]] = 0
		r := int32(0)
		for i := 1; i < m; i++ {
			cur, prev := sa[i], sa[i-1]
			if rank[cur] != rank[prev] || rank2(cur, k) != rank2(prev, k) {
				r++
			}
			tmp[cur] = r
		}
		copy(rank, tmp)
		if r == int32(m-1) || k > m {
			break
		}
	}
	return sa
}

// inverseBWT reconstructs the original string from its stored BWT last
// column and primary index.
func inverseBWT(l []byte, idx int) ([]byte, error) {
	n := len(l)
	if n == 0 {
		return []byte{}, nil
	}
	if idx < 0 || idx > n {
		return nil, ErrBWT
	}
	m := n + 1
	// Extended last column with the sentinel (-1) inserted at idx.
	lp := make([]int16, m)
	for i := 0; i < idx; i++ {
		lp[i] = int16(l[i])
	}
	lp[idx] = -1
	for i := idx; i < n; i++ {
		lp[i+1] = int16(l[i])
	}
	// LF mapping over the alphabet -1..255 (shifted by +1).
	var cnt [257]int
	for _, b := range lp {
		cnt[b+1]++
	}
	var start [257]int
	sum := 0
	for c := 0; c < 257; c++ {
		start[c] = sum
		sum += cnt[c]
	}
	next := make([]int32, m)
	var occ [257]int
	for i := 0; i < m; i++ {
		b := lp[i] + 1
		next[i] = int32(start[b] + occ[b])
		occ[b]++
	}
	// Walk: out[k] = lp[pos]; pos = next[pos], from the last position.
	out := make([]byte, n)
	pos := idx
	for k := m - 1; k >= 0; k-- {
		v := lp[pos]
		pos = int(next[pos])
		if v < 0 {
			if k != m-1 {
				return nil, ErrBWT
			}
			continue
		}
		out[k] = byte(v)
	}
	return out, nil
}
