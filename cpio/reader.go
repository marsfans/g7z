package cpio

import (
	"io"
	"strconv"
	"strings"
	"time"
)

const headerSize = 110

// Reader reads a newc/crc cpio stream entry by entry. It consumes
// exactly the bytes of each entry (no read-ahead), so wrapping it in a
// counting reader yields exact data offsets.
type Reader struct {
	r    io.Reader
	hdr  *Header // current entry, nil before the first Next
	left int64   // unread data bytes of the current entry
	pad  int64   // data padding bytes left to skip
	crc  bool    // current entry is from the crc variant
	sum  uint32  // running data checksum of the current entry
	done bool    // trailer seen
}

// NewReader returns a Reader reading from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

func pad4(n int64) int64 { return (4 - n%4) % 4 }

// skip discards the current entry's remaining data and padding,
// still accumulating the crc sum over skipped data bytes.
func (r *Reader) skip() error {
	n := r.left + r.pad
	if n == 0 {
		return nil
	}
	buf := make([]byte, 8192)
	for n > 0 {
		want := int64(len(buf))
		if n < want {
			want = n
		}
		m, err := io.ReadFull(r.r, buf[:want])
		if r.crc && r.left > 0 {
			take := int64(m)
			if take > r.left {
				take = r.left
			}
			for _, b := range buf[:take] {
				r.sum += uint32(b)
			}
		}
		r.left -= int64(m)
		if r.left < 0 {
			r.pad += r.left
			r.left = 0
		}
		n -= int64(m)
		if err != nil {
			return ErrTruncated
		}
	}
	r.pad = 0
	return nil
}

// finishEntry validates a completed crc entry. GNU cpio only
// checksums regular files (symlink targets, in particular, are
// stored with a zero check field), so other types are not validated.
func (r *Reader) finishEntry() error {
	if r.hdr != nil && r.crc && r.hdr.IsRegular() && r.sum != r.hdr.Check {
		return ErrChecksum
	}
	return nil
}

// Next advances to the next entry, skipping any unread data of the
// current one. It returns io.EOF at the trailer entry.
func (r *Reader) Next() (*Header, error) {
	if r.done {
		return nil, io.EOF
	}
	if r.hdr != nil {
		if err := r.skip(); err != nil {
			return nil, err
		}
		if err := r.finishEntry(); err != nil {
			return nil, err
		}
	}

	raw := make([]byte, headerSize)
	if _, err := io.ReadFull(r.r, raw); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, ErrTruncated
	}
	magic := string(raw[:6])
	var crc bool
	switch magic {
	case "070701":
	case "070702":
		crc = true
	default:
		return nil, ErrMalformed
	}
	field := func(i int) (uint32, error) {
		v, err := strconv.ParseUint(string(raw[6+i*8:6+(i+1)*8]), 16, 32)
		if err != nil {
			return 0, ErrMalformed
		}
		return uint32(v), nil
	}
	var vals [13]uint32
	for i := range vals {
		v, err := field(i)
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	nameSize := int64(vals[11])
	if nameSize < 1 || nameSize > 1<<20 {
		return nil, ErrMalformed
	}
	nameBuf := make([]byte, nameSize)
	if _, err := io.ReadFull(r.r, nameBuf); err != nil {
		return nil, ErrTruncated
	}
	if err := r.skipN(pad4(headerSize + nameSize)); err != nil {
		return nil, err
	}
	name := strings.TrimRight(string(nameBuf), "\x00")
	hdr := &Header{
		Ino:       vals[0],
		Mode:      vals[1],
		Uid:       vals[2],
		Gid:       vals[3],
		Nlink:     vals[4],
		ModTime:   time.Unix(int64(vals[5]), 0),
		Size:      int64(vals[6]),
		DevMajor:  vals[7],
		DevMinor:  vals[8],
		RDevMajor: vals[9],
		RDevMinor: vals[10],
		Check:     vals[12],
		Name:      name,
	}
	if name == "TRAILER!!!" {
		r.done = true
		return nil, io.EOF
	}
	r.hdr = hdr
	r.left = hdr.Size
	r.pad = pad4(hdr.Size)
	r.crc = crc
	r.sum = 0
	return hdr, nil
}

// skipN discards exactly n bytes (header/name padding).
func (r *Reader) skipN(n int64) error {
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		return ErrTruncated
	}
	return nil
}

// Read reads from the current entry's data.
func (r *Reader) Read(p []byte) (int, error) {
	if r.hdr == nil {
		return 0, io.EOF
	}
	if r.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		if r.crc {
			for _, b := range p[:n] {
				r.sum += uint32(b)
			}
		}
		r.left -= int64(n)
	}
	if err == io.EOF && r.left > 0 {
		err = ErrTruncated
	}
	return n, err
}
