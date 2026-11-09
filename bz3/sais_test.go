package bz3

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

// referenceSuffixArray is the original O(n log n) prefix-doubling
// implementation, kept as an independent cross-check for SA-IS.
func referenceSuffixArray(data []byte) []int32 {
	n := len(data)
	m := n + 1
	sa := make([]int32, m)
	rank := make([]int32, m)
	for i := 0; i < n; i++ {
		rank[i] = int32(data[i]) + 1
		sa[i] = int32(i)
	}
	rank[n] = 0
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
		maxRank := int32(0)
		for i := 0; i < m; i++ {
			if rank[i] > maxRank {
				maxRank = rank[i]
			}
		}
		cnt := make([]int32, maxRank+2)
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

// bruteForceSuffixArray sorts the suffixes of the sentinel-extended
// string by direct comparison.
func bruteForceSuffixArray(data []byte) []int32 {
	n := len(data)
	t := make([]int32, n+1)
	for i, b := range data {
		t[i] = int32(b) + 1
	}
	sa := make([]int32, n+1)
	for i := range sa {
		sa[i] = int32(i)
	}
	sort.Slice(sa, func(a, b int) bool {
		i, j := sa[a], sa[b]
		for i <= int32(n) && j <= int32(n) {
			if t[i] != t[j] {
				return t[i] < t[j]
			}
			i++
			j++
		}
		return false // suffixes are never equal (unique sentinel)
	})
	return sa
}

func equalSA(a, b []int32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSAISBruteForce sweeps small inputs over tiny alphabets, where
// heavy repetition stresses the LMS machinery, against brute force.
func TestSAISBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, alphabet := range []int{1, 2, 3, 5, 256} {
		for trial := 0; trial < 400; trial++ {
			n := rng.Intn(140)
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(rng.Intn(alphabet))
			}
			got := suffixArraySAIS(data)
			want := bruteForceSuffixArray(data)
			if !equalSA(got, want) {
				t.Fatalf("alphabet=%d data=%q:\n got %v\nwant %v", alphabet, data, got, want)
			}
		}
	}
	// Structured adversaries: all-same, periodic, and runs.
	patterns := [][]byte{
		bytes.Repeat([]byte("a"), 300),
		bytes.Repeat([]byte("ab"), 150),
		bytes.Repeat([]byte("abcab"), 60),
		bytes.Repeat([]byte("ba"), 150),
		[]byte("mississippi"),
		[]byte("banana"),
	}
	for _, data := range patterns {
		if got, want := suffixArraySAIS(data), bruteForceSuffixArray(data); !equalSA(got, want) {
			t.Fatalf("pattern %q...: SA mismatch", data[:16])
		}
	}
}

// TestSAISAgainstDoubling cross-checks SA-IS against the doubling
// implementation on larger, mixed inputs.
func TestSAISAgainstDoubling(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	cases := make([][]byte, 0, 24)
	for i := 0; i < 10; i++ { // full alphabet
		data := make([]byte, 1+rng.Intn(30000))
		rng.Read(data)
		cases = append(cases, data)
	}
	for i := 0; i < 10; i++ { // small alphabet, long repeats
		data := make([]byte, 1+rng.Intn(30000))
		for j := range data {
			data[j] = byte('a' + rng.Intn(4))
		}
		cases = append(cases, data)
	}
	// Word-salad text, like real encoder input.
	words := [][]byte{[]byte("the "), []byte("quick "), []byte("suffix "), []byte("array "), []byte("entropy ")}
	var buf bytes.Buffer
	for buf.Len() < 200000 {
		buf.Write(words[rng.Intn(len(words))])
	}
	cases = append(cases, buf.Bytes())
	cases = append(cases, bytes.Repeat([]byte("z"), 100000))

	for ci, data := range cases {
		if got, want := suffixArraySAIS(data), referenceSuffixArray(data); !equalSA(got, want) {
			t.Fatalf("case %d (len %d): SA mismatch", ci, len(data))
		}
	}
}

func benchData(n int) []byte {
	rng := rand.New(rand.NewSource(3))
	words := [][]byte{[]byte("the "), []byte("quick "), []byte("brown "), []byte("fox "), []byte("compression "), []byte("algorithm "), []byte("suffix "), []byte("array ")}
	var buf bytes.Buffer
	for buf.Len() < n {
		buf.Write(words[rng.Intn(len(words))])
	}
	return buf.Bytes()[:n]
}

func BenchmarkSAIS(b *testing.B) {
	data := benchData(4 << 20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suffixArraySAIS(data)
	}
}

func BenchmarkDoubling(b *testing.B) {
	data := benchData(4 << 20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		referenceSuffixArray(data)
	}
}
