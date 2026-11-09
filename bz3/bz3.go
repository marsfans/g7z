// Package bz3 is a pure Go implementation of the bzip3 compression format
// (.bz3), ported from the reference C implementation (libbz3) by Kamila
// Szewczyk. It is wire-compatible with the official bzip3 tools: files
// produced by the bzip3 CLI decode here, and files produced here decode
// with the official tools.
//
// The format is a blocked stream: a 9-byte header ("BZ3v1" + little-endian
// maximum block size) followed by chunks of (compressed size, original
// size, block payload). Each block runs RLE and LZP pre-filters, a
// Burrows-Wheeler transform, and a context-mixing arithmetic coder.
//
// License note: bzip3 is licensed under the GNU Lesser General Public
// License v3. This port is a derivative work and is distributed under the
// same license; see the LICENSE file in this directory.
package bz3

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Block size limits from the bzip3 format specification.
const (
	MinBlockSize = 65 * 1024         // 66,560 bytes
	MaxBlockSize = 511 * 1024 * 1024 // 535,822,336 bytes
	// DefaultBlockSize matches the official CLI default (16 MiB).
	DefaultBlockSize = 16 * 1024 * 1024
)

var (
	ErrMalformedHeader = errors.New("bz3: malformed header")
	ErrTruncatedData   = errors.New("bz3: truncated data")
	ErrCRC             = errors.New("bz3: CRC32 check failed")
	ErrBWT             = errors.New("bz3: Burrows-Wheeler transform failed")
	ErrDataTooBig      = errors.New("bz3: data too big")
	ErrInvalidBlockSz  = errors.New("bz3: invalid block size")
)

// bound returns the maximum size of a compressed block for the given
// uncompressed size, mirroring bz3_bound in the reference implementation.
func bound(size int) int { return size + size/50 + 50 }

func readS32(b []byte) int32 { return int32(binary.LittleEndian.Uint32(b)) }

func writeS32(b []byte, v int32) { binary.LittleEndian.PutUint32(b, uint32(v)) }

// checkBlockSize validates a block size against the format limits.
func checkBlockSize(n int) error {
	if n < MinBlockSize || n > MaxBlockSize {
		return fmt.Errorf("%w: %d", ErrInvalidBlockSz, n)
	}
	return nil
}
