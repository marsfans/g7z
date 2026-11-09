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
	sa := suffixArraySAIS(data)
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
