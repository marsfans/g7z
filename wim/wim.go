// Package wim reads and writes Windows Imaging Format (.wim)
// files. Reading supports stored, XPRESS and LZX resources
// (LZMS / solid "packed" resources are rejected); writing produces
// stored or XPRESS resources. Only the first image is exposed,
// which matches how single-image WIMs are used in practice.
package wim

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"
	"unicode/utf16"

	"github.com/Microsoft/go-winio/wim/lzx"
)

const (
	headerSize   = 208
	chunkSize    = 32768
	dentrySize   = 102 // fixed part of a directory entry
	reshdrSize   = 24
	lookupSize   = 50
	securitySize = 8

	flagHeaderCompression = 0x00000002
	flagHeaderCompressXP  = 0x00020000
	flagHeaderCompressLZX = 0x00040000
	flagHeaderCompressLZ  = 0x00080000

	reshdrFlagMetadata   = 0x02
	reshdrFlagCompressed = 0x04
	reshdrFlagPacked     = 0x10
)

type reshdr struct {
	size     int64 // low 56 bits of the first u64
	flags    byte  // high byte of the first u64
	offset   int64
	origSize int64
}

func parseReshdr(b []byte) reshdr {
	v := binary.LittleEndian.Uint64(b)
	return reshdr{
		size:     int64(v & 0x00FFFFFFFFFFFFFF),
		flags:    byte(v >> 56),
		offset:   int64(binary.LittleEndian.Uint64(b[8:])),
		origSize: int64(binary.LittleEndian.Uint64(b[16:])),
	}
}

func (r reshdr) marshal() []byte {
	b := make([]byte, reshdrSize)
	v := uint64(r.size&0x00FFFFFFFFFFFFFF) | uint64(r.flags)<<56
	binary.LittleEndian.PutUint64(b, v)
	binary.LittleEndian.PutUint64(b[8:], uint64(r.offset))
	binary.LittleEndian.PutUint64(b[16:], uint64(r.origSize))
	return b
}

type lookupEntry struct {
	reshdr
	part   uint16
	refcnt uint32
	hash   [20]byte
}

// Entry is one file or directory in an image.
type Entry struct {
	Name       string // full path, "/" separated
	Size       int64
	ModTime    time.Time
	Mode       fs.FileMode
	IsDir      bool
	HardlinkTo string // path of the first entry sharing the content

	hash [20]byte
	ent  *lookupEntry // content resource (nil for empty files/dirs)
}

// Reader is an opened WIM file.
type Reader struct {
	r          io.ReaderAt
	size       int64
	flags      uint32
	chunk      int64
	images     int
	byHash     map[[20]byte]*lookupEntry
	metadata   []*lookupEntry // per image, in order
	compressor int            // 0 stored, 1 XPRESS, 2 LZX, 3 LZMS
}

// OpenReader parses the header and lookup table of a WIM file.
func OpenReader(r io.ReaderAt, size int64) (*Reader, error) {
	hdr := make([]byte, headerSize)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("wim: cannot read header: %w", err)
	}
	if string(hdr[:8]) != "MSWIM\x00\x00\x00" {
		return nil, errors.New("wim: bad magic")
	}
	if n := binary.LittleEndian.Uint32(hdr[8:]); n != headerSize {
		return nil, fmt.Errorf("wim: unsupported header size %d", n)
	}
	rd := &Reader{r: r, size: size}
	rd.flags = binary.LittleEndian.Uint32(hdr[16:])
	rd.chunk = int64(binary.LittleEndian.Uint32(hdr[20:]))
	rd.images = int(binary.LittleEndian.Uint32(hdr[44:]))
	switch {
	case rd.flags&flagHeaderCompressLZ != 0:
		rd.compressor = 3
	case rd.flags&flagHeaderCompressLZX != 0:
		rd.compressor = 2
	case rd.flags&flagHeaderCompressXP != 0:
		rd.compressor = 1
	}
	if rd.chunk == 0 {
		rd.chunk = chunkSize
	}
	ot := parseReshdr(hdr[48:])
	if ot.size%lookupSize != 0 {
		return nil, fmt.Errorf("wim: lookup table size %d is not a multiple of %d", ot.size, lookupSize)
	}
	raw := make([]byte, ot.size)
	if _, err := r.ReadAt(raw, ot.offset); err != nil {
		return nil, fmt.Errorf("wim: cannot read lookup table: %w", err)
	}
	rd.byHash = map[[20]byte]*lookupEntry{}
	for i := 0; i+lookupSize <= len(raw); i += lookupSize {
		e := &lookupEntry{reshdr: parseReshdr(raw[i:])}
		e.part = binary.LittleEndian.Uint16(raw[i+24:])
		e.refcnt = binary.LittleEndian.Uint32(raw[i+26:])
		copy(e.hash[:], raw[i+30:i+50])
		if e.flags&reshdrFlagMetadata != 0 {
			rd.metadata = append(rd.metadata, e)
		} else {
			rd.byHash[e.hash] = e
		}
	}
	if len(rd.metadata) < rd.images {
		return nil, fmt.Errorf("wim: %d images but %d metadata resources", rd.images, len(rd.metadata))
	}
	return rd, nil
}

// ImageCount returns the number of images in the file.
func (rd *Reader) ImageCount() int { return rd.images }

// readResource returns the decompressed contents of a resource.
func (rd *Reader) readResource(e *lookupEntry) ([]byte, error) {
	if e.flags&reshdrFlagPacked != 0 {
		return nil, errors.New("wim: solid (LZMS packed) resources are not supported")
	}
	raw := make([]byte, e.size)
	if _, err := rd.r.ReadAt(raw, e.offset); err != nil {
		return nil, fmt.Errorf("wim: cannot read resource: %w", err)
	}
	if e.size == e.origSize {
		return raw, nil
	}
	// Chunked compression: chunk table of offsets relative to the
	// end of the table, then the chunks themselves.
	if rd.compressor == 3 {
		return nil, errors.New("wim: LZMS resources are not supported")
	}
	if rd.compressor == 0 {
		return nil, fmt.Errorf("wim: resource is compressed (%d -> %d) but the header declares no compression", e.size, e.origSize)
	}
	nchunks := int((e.origSize + rd.chunk - 1) / rd.chunk)
	entrySize := 4
	if e.origSize > 0xFFFFFFFF {
		entrySize = 8
	}
	tableSize := int64(nchunks-1) * int64(entrySize)
	if int64(len(raw)) < tableSize {
		return nil, errors.New("wim: resource too small for its chunk table")
	}
	offs := make([]int64, nchunks+1)
	offs[0] = tableSize
	for i := 1; i < nchunks; i++ {
		if entrySize == 4 {
			offs[i] = int64(binary.LittleEndian.Uint32(raw[(i-1)*4:]))
		} else {
			offs[i] = int64(binary.LittleEndian.Uint64(raw[(i-1)*8:]))
		}
		offs[i] += tableSize
	}
	offs[nchunks] = e.size
	out := make([]byte, 0, e.origSize)
	for i := 0; i < nchunks; i++ {
		chunk := raw[offs[i]:offs[i+1]]
		unc := rd.chunk
		if rem := e.origSize - int64(i)*rd.chunk; rem < unc {
			unc = rem
		}
		if int64(len(chunk)) == unc {
			out = append(out, chunk...)
			continue
		}
		var dec []byte
		var err error
		switch rd.compressor {
		case 1:
			dec, err = xpressDecompressChunk(chunk, int(unc))
		case 2:
			var zr io.ReadCloser
			zr, err = lzx.NewReader(bytes.NewReader(chunk), int(unc))
			if err == nil {
				dec, err = io.ReadAll(zr)
				zr.Close()
			}
		}
		if err != nil {
			return nil, fmt.Errorf("wim: chunk %d: %w", i, err)
		}
		if int64(len(dec)) != unc {
			return nil, fmt.Errorf("wim: chunk %d decompressed to %d bytes, want %d", i, len(dec), unc)
		}
		out = append(out, dec...)
	}
	return out, nil
}

// dentry is a parsed metadata directory entry.
type dentry struct {
	attrs    uint32
	suboff   int64
	ctime    uint64
	atime    uint64
	wtime    uint64
	hash     [20]byte
	name     string
	children []*dentry
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// FILETIME: 100 ns ticks since 1601-01-01.
	return time.Unix(0, (int64(ft)-116444736000000000)*100).UTC()
}

func parseDentryTree(meta []byte) (*dentry, error) {
	if len(meta) < securitySize {
		return nil, errors.New("wim: metadata too small")
	}
	secSize := int64(int32(binary.LittleEndian.Uint32(meta)))
	if secSize < securitySize || secSize > int64(len(meta)) {
		return nil, fmt.Errorf("wim: bad security block size %d", secSize)
	}
	return parseDentry(meta, secSize, 0)
}

func parseDentry(meta []byte, off int64, depth int) (*dentry, error) {
	if depth > 64 {
		return nil, errors.New("wim: directory tree too deep")
	}
	if off+8 > int64(len(meta)) {
		return nil, fmt.Errorf("wim: dentry offset %d out of bounds", off)
	}
	length := int64(binary.LittleEndian.Uint64(meta[off:]))
	if length == 0 {
		return nil, nil // end-of-list tag
	}
	if length < dentrySize || off+length > int64(len(meta)) {
		return nil, fmt.Errorf("wim: bad dentry length %d at %d", length, off)
	}
	b := meta[off : off+length]
	d := &dentry{}
	d.attrs = binary.LittleEndian.Uint32(b[8:])
	d.suboff = int64(binary.LittleEndian.Uint64(b[16:]))
	d.ctime = binary.LittleEndian.Uint64(b[40:])
	d.atime = binary.LittleEndian.Uint64(b[48:])
	d.wtime = binary.LittleEndian.Uint64(b[56:])
	copy(d.hash[:], b[64:84])
	nStreams := int(binary.LittleEndian.Uint16(b[96:]))
	shortLen := int(binary.LittleEndian.Uint16(b[98:]))
	longLen := int(binary.LittleEndian.Uint16(b[100:]))
	p := dentrySize
	if p+longLen > len(b) {
		return nil, errors.New("wim: dentry name out of bounds")
	}
	d.name = utf16Decode(b[p : p+longLen])
	p += longLen + shortLen
	// Skip alternate data stream entries.
	for i := 0; i < nStreams && p+8 <= len(b); i++ {
		sl := int(binary.LittleEndian.Uint64(b[p:]))
		if sl < 36 || p+sl > len(b) {
			break
		}
		p += sl
	}
	if d.suboff != 0 {
		for childOff := d.suboff; ; {
			if childOff+8 > int64(len(meta)) {
				return nil, fmt.Errorf("wim: child offset %d out of bounds", childOff)
			}
			if binary.LittleEndian.Uint64(meta[childOff:]) == 0 {
				break
			}
			child, err := parseDentry(meta, childOff, depth+1)
			if err != nil {
				return nil, err
			}
			if child == nil {
				break
			}
			d.children = append(d.children, child)
			childOff += int64(binary.LittleEndian.Uint64(meta[childOff:]))
		}
	}
	return d, nil
}

func utf16Decode(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func utf16Encode(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

var zeroHash [20]byte

// Image returns the flattened entries of image index (1-based).
func (rd *Reader) Image(index int) ([]*Entry, error) {
	if index < 1 || index > len(rd.metadata) {
		return nil, fmt.Errorf("wim: image %d out of range", index)
	}
	meta, err := rd.readResource(rd.metadata[index-1])
	if err != nil {
		return nil, err
	}
	root, err := parseDentryTree(meta)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, errors.New("wim: empty metadata")
	}
	var out []*Entry
	seen := map[[20]byte]string{}
	var walk func(d *dentry, prefix string) error
	walk = func(d *dentry, prefix string) error {
		for _, c := range d.children {
			name := prefix + c.name
			e := &Entry{
				Name:    name,
				ModTime: filetimeToTime(c.wtime),
				hash:    c.hash,
			}
			if c.attrs&0x10 != 0 || c.suboff != 0 {
				e.IsDir = true
				e.Mode = 0755
				if c.attrs&0x1 != 0 {
					e.Mode = 0555
				}
			} else {
				e.Mode = 0644
				if c.attrs&0x1 != 0 {
					e.Mode = 0444
				}
				if c.hash != zeroHash {
					le, ok := rd.byHash[c.hash]
					if !ok {
						return fmt.Errorf("wim: no resource for file %s", name)
					}
					e.ent = le
					e.Size = le.origSize
					if first, dup := seen[c.hash]; dup {
						e.HardlinkTo = first
					} else {
						seen[c.hash] = name
					}
				}
			}
			out = append(out, e)
			if e.IsDir {
				if err := walk(c, name+"/"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// Open returns the decompressed contents of a file entry.
func (rd *Reader) Open(e *Entry) (io.ReadCloser, error) {
	if e.ent == nil {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	data, err := rd.readResource(e.ent)
	if err != nil {
		return nil, err
	}
	if sha1.Sum(data) != e.hash {
		return nil, fmt.Errorf("wim: SHA-1 mismatch for %s", e.Name)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
