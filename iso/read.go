package iso

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Reader is a parsed ISO 9660 image. Rock Ridge names, modes
// and timestamps are honoured when present; otherwise the plain
// ISO names (upper-case, version suffix stripped) are used.
type Reader struct {
	r    io.ReaderAt
	root *File
}

// File is one directory entry in the image.
type File struct {
	Name    string // single path component
	Size    int64
	ModTime time.Time
	Mode    os.FileMode
	IsDir   bool

	img      *Reader
	extents  []extent
	children []*File
	parsed   bool
}

type extent struct {
	loc  uint32
	size uint32
}

// Open parses the primary volume descriptor of the image.
func Open(r io.ReaderAt) (*Reader, error) {
	pvd := make([]byte, blockSize)
	if _, err := r.ReadAt(pvd, 16*blockSize); err != nil {
		return nil, fmt.Errorf("iso: cannot read volume descriptor: %w", err)
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return nil, errors.New("iso: no primary volume descriptor (not an ISO 9660 image)")
	}
	rd := &Reader{r: r}
	root, err := rd.parseRecord(pvd[156:190], true)
	if err != nil {
		return nil, err
	}
	rd.root = root
	return rd, nil
}

// Root returns the image's root directory.
func (rd *Reader) Root() *File { return rd.root }

// Children lists a directory's entries (excluding "." and "..").
func (f *File) Children() ([]*File, error) {
	if !f.IsDir {
		return nil, errors.New("iso: not a directory")
	}
	if f.parsed {
		return f.children, nil
	}
	f.parsed = true
	if len(f.extents) == 0 {
		return nil, nil
	}
	ext := f.extents[0]
	data := make([]byte, ext.size)
	if _, err := f.img.r.ReadAt(data, int64(ext.loc)*blockSize); err != nil {
		return nil, err
	}
	var raw [][]byte
	for off := 0; off < len(data); {
		l := int(data[off])
		if l == 0 {
			// Padding to the end of the current block.
			off = (off/blockSize + 1) * blockSize
			continue
		}
		if off+l > len(data) {
			return nil, errors.New("iso: corrupt directory record")
		}
		raw = append(raw, data[off:off+l])
		off += l
	}
	for i := 0; i < len(raw); i++ {
		rec := raw[i]
		if len(rec) < 34 {
			continue
		}
		nameByte := rec[33]
		if rec[32] == 1 && (nameByte == 0 || nameByte == 1) {
			continue // "." and ".."
		}
		child, err := f.img.parseRecord(rec, false)
		if err != nil {
			return nil, err
		}
		// Multi-extent files: consecutive records with the same
		// name and the continuation flag set on all but the last.
		for rec[25]&0x80 != 0 && i+1 < len(raw) {
			i++
			rec = raw[i]
			next, err := f.img.parseRecord(rec, false)
			if err != nil {
				return nil, err
			}
			child.extents = append(child.extents, next.extents...)
			child.Size += next.Size
		}
		f.children = append(f.children, child)
	}
	return f.children, nil
}

// Open returns a reader for the file's content.
func (f *File) Open() io.Reader {
	var parts []io.Reader
	for _, e := range f.extents {
		parts = append(parts, io.NewSectionReader(f.img.r, int64(e.loc)*blockSize, int64(e.size)))
	}
	return io.MultiReader(parts...)
}

func (rd *Reader) parseRecord(rec []byte, isRoot bool) (*File, error) {
	if len(rec) < 33 {
		return nil, errors.New("iso: short directory record")
	}
	f := &File{img: rd}
	loc := binary.LittleEndian.Uint32(rec[2:])
	size := binary.LittleEndian.Uint32(rec[10:])
	f.extents = []extent{{loc, size}}
	f.Size = int64(size)
	f.IsDir = rec[25]&2 != 0
	f.ModTime = parseRecordDate(rec[18:25])
	nameLen := int(rec[32])
	if 33+nameLen > len(rec) {
		return nil, errors.New("iso: corrupt file identifier")
	}
	isoName := string(rec[33 : 33+nameLen])
	suspOff := 33 + nameLen
	if nameLen%2 == 0 {
		suspOff++
	}
	var susp []byte
	if suspOff < len(rec) {
		susp = rec[suspOff:]
	}
	rr := rd.parseSUSP(susp)
	if rr.name != "" {
		f.Name = rr.name
	} else if isRoot {
		f.Name = ""
	} else if isoName == "\x00" {
		f.Name = "."
	} else if isoName == "\x01" {
		f.Name = ".."
	} else {
		f.Name = strings.TrimSuffix(isoName, ";1")
	}
	if rr.hasMode {
		f.Mode = rr.mode
	} else if f.IsDir {
		f.Mode = os.ModeDir | 0755
	} else {
		f.Mode = 0644
	}
	if f.IsDir {
		f.Mode |= os.ModeDir
	}
	if !rr.mtime.IsZero() {
		f.ModTime = rr.mtime
	}
	return f, nil
}

type rrInfo struct {
	name    string
	mode    os.FileMode
	hasMode bool
	mtime   time.Time
}

// rrAcc accumulates Rock Ridge data across a record's system use
// area and any CE continuation areas it points to.
type rrAcc struct {
	info   rrInfo
	nm     []byte
	nmDone bool
}

// parseSUSP walks SUSP entries, following CE continuation areas
// (which may nest) to gather NM, PX and TF data.
func (rd *Reader) parseSUSP(b []byte) rrInfo {
	acc := &rrAcc{}
	rd.suspWalk(b, acc)
	acc.info.name = string(acc.nm)
	return acc.info
}

func (rd *Reader) suspWalk(b []byte, acc *rrAcc) {
	for len(b) >= 4 {
		l := int(b[2])
		if l < 4 || l > len(b) {
			break
		}
		entry := b[:l]
		switch string(entry[:2]) {
		case "NM":
			if len(entry) >= 5 && !acc.nmDone {
				acc.nm = append(acc.nm, entry[5:]...)
				if entry[4]&1 == 0 {
					acc.nmDone = true
				}
			}
		case "PX":
			if len(entry) >= 12 && !acc.info.hasMode {
				m := binary.LittleEndian.Uint32(entry[4:])
				acc.info.mode = os.FileMode(m & 0o7777)
				acc.info.hasMode = true
			}
		case "TF":
			if acc.info.mtime.IsZero() {
				acc.info.mtime = parseTF(entry)
			}
		case "CE":
			if len(entry) >= 28 {
				blk := binary.LittleEndian.Uint32(entry[4:])
				off := binary.LittleEndian.Uint32(entry[12:])
				length := binary.LittleEndian.Uint32(entry[20:])
				buf := make([]byte, length)
				if _, err := rd.r.ReadAt(buf, int64(blk)*blockSize+int64(off)); err == nil {
					rd.suspWalk(buf, acc)
				}
			}
		}
		b = b[l:]
	}
}

// parseTF extracts the modification time (or creation, failing
// that) from a TF entry.
func parseTF(e []byte) time.Time {
	if len(e) < 5 {
		return time.Time{}
	}
	flags := e[4]
	longForm := flags&0x80 != 0
	step := 7
	if longForm {
		step = 17
	}
	off := 5
	var creation, mtime time.Time
	for i := 0; i < 7; i++ {
		if flags&(1<<uint(i)) == 0 {
			continue
		}
		if off+step > len(e) {
			break
		}
		var t time.Time
		if longForm {
			t = parseVolumeDate(e[off : off+17])
		} else {
			t = parseRecordDate(e[off : off+7])
		}
		switch i {
		case 0:
			creation = t
		case 1:
			mtime = t
		}
		off += step
	}
	if !mtime.IsZero() {
		return mtime
	}
	return creation
}

// parseRecordDate decodes the 7-byte directory timestamp.
func parseRecordDate(b []byte) time.Time {
	if len(b) < 7 {
		return time.Time{}
	}
	year := int(b[0]) + 1900
	if year < 1970 || int(b[1]) < 1 || int(b[1]) > 12 || int(b[2]) < 1 || int(b[2]) > 31 {
		return time.Time{}
	}
	loc := time.FixedZone("", int(int8(b[6]))*900)
	return time.Date(year, time.Month(b[1]), int(b[2]), int(b[3]), int(b[4]), int(b[5]), 0, loc)
}

// parseVolumeDate decodes the 17-byte volume timestamp:
// YYYYMMDDHHMMSSCC followed by a signed timezone byte.
func parseVolumeDate(b []byte) time.Time {
	if len(b) < 17 {
		return time.Time{}
	}
	year, err := atoi2(string(b[0:4]))
	if err != nil || year == 0 {
		return time.Time{}
	}
	var f [6]int // month, day, hour, minute, second, centisecond
	for i := range f {
		n, err := atoi2(string(b[4+i*2 : 6+i*2]))
		if err != nil {
			return time.Time{}
		}
		f[i] = n
	}
	loc := time.FixedZone("", int(int8(b[16]))*900)
	return time.Date(year, time.Month(f[0]), f[1], f[2], f[3], f[4], f[5]*10000000, loc)
}

func atoi2(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
