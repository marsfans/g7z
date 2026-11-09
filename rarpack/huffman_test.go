package rarpack

import (
	"math/rand"
	"testing"
)

func TestHuffmanLengths(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 300; trial++ {
		n := 2 + rng.Intn(305)
		freq := make([]uint32, n)
		mode := trial % 3
		for i := range freq {
			switch mode {
			case 0: // fibonacci-like worst case for depth
				a, b := uint32(1), uint32(1)
				for j := 0; j < i%30; j++ {
					a, b = b, a+b
				}
				freq[i] = a
			case 1: // skewed
				if rng.Intn(10) < 9 {
					freq[i] = uint32(rng.Intn(3))
				} else {
					freq[i] = uint32(rng.Intn(100000))
				}
			default:
				freq[i] = uint32(rng.Intn(1000))
			}
		}
		lens := buildLengths(freq, 15)
		used := 0
		for _, l := range lens {
			if l > 15 {
				t.Fatalf("trial %d: length %d > 15", trial, l)
			}
			if l > 0 {
				used++
			}
		}
		if used >= 2 && !kraftOK(lens, 15) {
			t.Fatalf("trial %d (mode %d): Kraft sum not complete", trial, mode)
		}
	}
}
