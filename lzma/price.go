// Copyright 2014-2022 Ulrich Kunitz. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

// Price computation for the optimal parser. Prices are in units of
// 1/16 bit, following liblzma's rangecoder price model (Igor Pavlov,
// 0BSD). The lookup table is the generated lzma_rc_prices table from
// liblzma (price_table.c).

var rcPrices = [128]uint8{
	128, 103, 91, 84, 78, 73, 69, 66,
	63, 61, 58, 56, 54, 52, 51, 49,
	48, 46, 45, 44, 43, 42, 41, 40,
	39, 38, 37, 36, 35, 34, 34, 33,
	32, 31, 31, 30, 29, 29, 28, 28,
	27, 26, 26, 25, 25, 24, 24, 23,
	23, 22, 22, 22, 21, 21, 20, 20,
	19, 19, 19, 18, 18, 17, 17, 17,
	16, 16, 16, 15, 15, 15, 14, 14,
	14, 13, 13, 13, 12, 12, 12, 11,
	11, 11, 11, 10, 10, 10, 10, 9,
	9, 9, 9, 8, 8, 8, 8, 7,
	7, 7, 7, 6, 6, 6, 6, 5,
	5, 5, 5, 5, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 2, 2, 2,
	2, 2, 2, 1, 1, 1, 1, 1,
}

// bitPrice returns the price of encoding bit with probability p.
// p models the probability of the bit being zero (11-bit range).
func bitPrice(p prob, bit uint32) uint32 {
	return uint32(rcPrices[(uint32(p)^((0-bit)&2047))>>4])
}

// bit0Price returns the price of encoding a zero bit.
func bit0Price(p prob) uint32 {
	return uint32(rcPrices[uint32(p)>>4])
}

// bit1Price returns the price of encoding a one bit.
func bit1Price(p prob) uint32 {
	return uint32(rcPrices[(uint32(p)^2047)>>4])
}

// bittreePrice returns the price of encoding v with the tree codec
// whose probabilities are given (MSB first, root at index 1).
func bittreePrice(probs []prob, bits uint, v uint32) uint32 {
	price := uint32(0)
	m := uint32(1)
	for i := int(bits) - 1; i >= 0; i-- {
		b := (v >> uint(i)) & 1
		price += bitPrice(probs[m], b)
		m = (m << 1) | b
	}
	return price
}

// bittreeReversePrice returns the price of encoding v with the
// reverse tree codec (LSB first).
func bittreeReversePrice(probs []prob, bits uint, v uint32) uint32 {
	price := uint32(0)
	m := uint32(1)
	for i := uint(0); i < bits; i++ {
		b := (v >> i) & 1
		price += bitPrice(probs[m], b)
		m = (m << 1) | b
	}
	return price
}

// directPrice returns the price of encoding nbits direct bits.
func directPrice(nbits uint32) uint32 {
	return nbits << 4
}
