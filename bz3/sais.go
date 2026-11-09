package bz3

// SA-IS suffix array construction (Nong, Zhang & Chan 2009), for the
// sentinel-terminated integer alphabets used by the BWT: symbols are in
// [0, k) and the final symbol is a unique 0 sentinel, smaller than every
// other symbol. Runs in O(n) time and replaces the O(n log n) prefix
// doubling used initially.

// suffixArraySAIS returns the suffix array of data extended with a
// unique sentinel at position len(data).
func suffixArraySAIS(data []byte) []int32 {
	n := len(data)
	t := make([]int32, n+1)
	for i, b := range data {
		t[i] = int32(b) + 1
	}
	t[n] = 0
	return sais(t, 257)
}

// sais returns the suffix array of t. t must end with a unique 0
// sentinel and all its symbols must lie in [0, k).
func sais(t []int32, k int) []int32 {
	m := len(t)
	sa := make([]int32, m)
	if m == 1 {
		sa[0] = 0
		return sa
	}

	// Classify each position as S-type (true) or L-type (false).
	isS := make([]bool, m)
	isS[m-1] = true
	for i := m - 2; i >= 0; i-- {
		if t[i] != t[i+1] {
			isS[i] = t[i] < t[i+1]
		} else {
			isS[i] = isS[i+1]
		}
	}
	isLMS := func(i int) bool { return i > 0 && isS[i] && !isS[i-1] }

	// Bucket boundaries: start[c] is the first slot of bucket c,
	// end[c] is one past its last slot.
	counts := make([]int32, k)
	for _, c := range t {
		counts[c]++
	}
	start := make([]int32, k)
	end := make([]int32, k)
	{
		s := int32(0)
		for c := 0; c < k; c++ {
			start[c] = s
			s += counts[c]
			end[c] = s
		}
	}

	// induce fills sa by induced sorting: the LMS positions given in
	// lmsOrder are seeded at bucket tails in that order, then L-type
	// suffixes are induced left to right and S-type right to left.
	induce := func(lmsOrder []int32) {
		for i := range sa {
			sa[i] = -1
		}
		ptr := make([]int32, k)
		copy(ptr, end)
		for i := len(lmsOrder) - 1; i >= 0; i-- {
			p := lmsOrder[i]
			c := t[p]
			ptr[c]--
			sa[ptr[c]] = p
		}
		copy(ptr, start)
		for i := 0; i < m; i++ {
			s := sa[i]
			if s > 0 && !isS[s-1] {
				c := t[s-1]
				sa[ptr[c]] = s - 1
				ptr[c]++
			}
		}
		copy(ptr, end)
		for i := m - 1; i >= 0; i-- {
			s := sa[i]
			if s > 0 && isS[s-1] {
				c := t[s-1]
				ptr[c]--
				sa[ptr[c]] = s - 1
			}
		}
	}

	// LMS positions in text order.
	lmsPos := make([]int32, 0, m/2+1)
	for i := 1; i < m; i++ {
		if isLMS(i) {
			lmsPos = append(lmsPos, int32(i))
		}
	}
	m1 := len(lmsPos)

	// Induced sorting from the text-order LMS seeds leaves the LMS
	// suffixes ordered by their LMS substrings.
	induce(lmsPos)
	sortedLMS := make([]int32, 0, m1)
	for _, s := range sa {
		if isLMS(int(s)) {
			sortedLMS = append(sortedLMS, s)
		}
	}

	// Name the LMS substrings in sorted order. An LMS substring spans
	// from its LMS position up to and including the next LMS position.
	nextLMS := make([]int32, m)
	for i := 0; i+1 < m1; i++ {
		nextLMS[lmsPos[i]] = lmsPos[i+1]
	}
	substrLen := func(p int32) int {
		if int(p) == m-1 {
			return 1
		}
		return int(nextLMS[p]) - int(p) + 1
	}
	substrEqual := func(a, b int32) bool {
		la, lb := substrLen(a), substrLen(b)
		if la != lb {
			return false
		}
		for d := int32(0); d < int32(la); d++ {
			if t[a+d] != t[b+d] || isS[a+d] != isS[b+d] {
				return false
			}
		}
		return true
	}
	nameOf := make([]int32, m)
	var name int32 = -1
	prev := int32(-1)
	for _, p := range sortedLMS {
		if prev < 0 || !substrEqual(prev, p) {
			name++
		}
		nameOf[p] = name
		prev = p
	}
	distinct := int(name) + 1

	// The reduced string lists the names in text order; its last symbol
	// is the sentinel's name, always 0, so it again ends in a unique 0.
	t1 := make([]int32, m1)
	for i, p := range lmsPos {
		t1[i] = nameOf[p]
	}
	nameOf = nil

	var sa1 []int32
	if distinct == m1 {
		sa1 = make([]int32, m1)
		for i, nm := range t1 {
			sa1[nm] = int32(i)
		}
	} else {
		sa1 = sais(t1, distinct)
	}

	// Final induced sort with the LMS positions in true suffix order.
	orderedLMS := make([]int32, m1)
	for i, idx := range sa1 {
		orderedLMS[i] = lmsPos[idx]
	}
	induce(orderedLMS)
	return sa
}
