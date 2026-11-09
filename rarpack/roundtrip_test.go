package rarpack

import "testing"

// Simulate UnRAR's SlotToLength.
func slotToLength(slot int, extra uint32) int {
	length := 2
	if slot < 8 {
		return length + slot
	}
	lbits := slot/4 - 1
	length += (4 | (slot & 3)) << uint(lbits)
	length += int(extra)
	return length
}

// Simulate UnRAR's distance reconstruction (returns decoder Distance).
func decodeDistance(slot, dBits int, hi uint32, ldd int, lo uint32) int {
	dist := 1
	if slot < 4 {
		return dist + slot
	}
	dist += (2 | (slot & 1)) << uint(dBits)
	if dBits >= 4 {
		dist += int(hi) << 4
		dist += ldd
	} else if dBits > 0 {
		dist += int(lo)
	}
	return dist
}

func TestLengthRoundTrip(t *testing.T) {
	for encLen := 2; encLen <= 4097; encLen++ {
		slot, extra, bits := encodeLength(encLen)
		if slot > 43 {
			t.Fatalf("encLen %d slot %d > 43", encLen, slot)
		}
		got := slotToLength(slot, extra)
		// account for the extra-bits width: decoder reads exactly `bits` bits
		if bits == 0 && extra != 0 {
			t.Fatalf("encLen %d: extra without bits", encLen)
		}
		if got != encLen {
			t.Fatalf("encLen %d -> slot %d extra %d bits %d -> %d", encLen, slot, extra, bits, got)
		}
	}
}

func TestDistanceRoundTrip(t *testing.T) {
	for dist := 1; dist <= dictSize; dist++ {
		slot, dBits, hi, needLDD, ldd, lo := encodeDistance(dist)
		if slot >= dcSize {
			t.Fatalf("dist %d slot %d out of range", dist, slot)
		}
		expDBits := 0
		if slot >= 4 {
			expDBits = slot/2 - 1
		}
		if dBits != expDBits {
			t.Fatalf("dist %d: dBits %d != decoder %d", dist, dBits, expDBits)
		}
		if needLDD != (dBits >= 4) {
			t.Fatalf("dist %d: needLDD mismatch", dist)
		}
		got := decodeDistance(slot, dBits, hi, ldd, lo)
		if got != dist {
			t.Fatalf("dist %d -> slot %d dBits %d hi %d ldd %d lo %d -> %d", dist, slot, dBits, hi, ldd, lo, got)
		}
	}
}
