package bz3

// The reference implementation uses a table-driven CRC-32 with the
// reflected Castagnoli polynomial (0x82F63B78), an initial value of 1 and
// no final complement: crc32sum(1, data). The table below is generated
// from the polynomial; it is identical to the table in libbz3.c.

var crc32Table [256]uint32

func init() {
	const poly = 0x82F63B78
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		crc32Table[i] = crc
	}
}

// crc32sum continues a CRC computation exactly like the reference
// crc32sum: no pre/post complement is applied by this function.
func crc32sum(crc uint32, buf []byte) uint32 {
	for _, b := range buf {
		crc = crc32Table[byte(crc)^b] ^ (crc >> 8)
	}
	return crc
}

// blockCRC computes the checksum stored in block headers.
func blockCRC(data []byte) uint32 { return crc32sum(1, data) }
