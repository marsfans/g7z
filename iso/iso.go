// Package iso writes ISO 9660 images with Rock Ridge extensions
// (NM/PX/TF system use entries), so long file names, POSIX modes
// and timestamps survive alongside the plain mangled ISO names
// that simple readers fall back to. Name components too long for
// a directory record spill into a SUSP continuation area.
// Single-extent files up to 4 GiB; no Joliet tree.
package iso

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const blockSize = 2048

// Entry is one file or directory to place in the image. Name is
// the full path from the image root with '/' separators and no
// leading slash. Open supplies a file's content; it is called
// once, after layout, and must produce exactly Size bytes.
type Entry struct {
	Name    string
	Size    int64
	ModTime time.Time
	Mode    os.FileMode
	IsDir   bool
	Open    func() (io.ReadCloser, error)
}

type node struct {
	name     string // real path component
	isoName  string // mangled ISO 9660 identifier (no ";1")
	isDir    bool
	entry    *Entry // nil for implicit directories
	parent   *node
	children []*node
	extent   uint32
	size     uint32 // directory: padded record bytes; file: data size
	ceExtent uint32 // SUSP continuation area extent (0 = none)
	ceSize   uint32 // padded continuation area size
	index    uint16 // path table index (directories, 1-based)
}

// Create writes a complete ISO 9660 + Rock Ridge image holding
// files to w. volumeID is sanitised to a valid volume identifier.
func Create(w io.Writer, volumeID string, files []*Entry) error {
	now := time.Now()
	root := &node{name: "", isDir: true}
	byPath := map[string]*node{"": root}
	var getDir func(p string) *node
	getDir = func(p string) *node {
		if n, ok := byPath[p]; ok {
			return n
		}
		parent := getDir(parentPath(p))
		n := &node{name: baseName(p), isDir: true, parent: parent}
		parent.children = append(parent.children, n)
		byPath[p] = n
		return n
	}
	for _, f := range files {
		name := strings.Trim(f.Name, "/")
		if name == "" {
			continue
		}
		if f.IsDir {
			getDir(name).entry = f
			continue
		}
		if f.Size > 0xFFFFFFFF {
			return fmt.Errorf("iso: %s exceeds the 4 GiB single-extent limit", f.Name)
		}
		parent := getDir(parentPath(name))
		n := &node{name: baseName(name), entry: f, parent: parent, size: uint32(f.Size)}
		parent.children = append(parent.children, n)
		byPath[name] = n
	}

	// Mangle ISO names per directory, resolving collisions.
	var mangle func(n *node)
	mangle = func(n *node) {
		used := map[string]bool{}
		for _, c := range n.children {
			c.isoName = mangleName(c.name, c.isDir, used)
		}
		sort.Slice(n.children, func(i, j int) bool {
			return recordKey(n.children[i]) < recordKey(n.children[j])
		})
		for _, c := range n.children {
			if c.isDir {
				mangle(c)
			}
		}
	}
	mangle(root)

	// Directory list in path-table (breadth-first) order.
	dirs := []*node{root}
	for i := 0; i < len(dirs); i++ {
		dirs[i].index = uint16(i + 1)
		for _, c := range dirs[i].children {
			if c.isDir {
				dirs = append(dirs, c)
			}
		}
	}

	// Record sizes do not depend on extent values, so measure
	// every directory (and its continuation area) up front.
	for _, d := range dirs {
		recs, ce := buildDirRecords(d, now, 0)
		d.size = uint32(len(recs))
		if len(ce) > 0 {
			d.ceSize = uint32((len(ce) + blockSize - 1) / blockSize * blockSize)
		}
	}

	ptSize := 0
	for _, d := range dirs {
		l := 8 + len(pathTableName(d))
		if l%2 == 1 {
			l++
		}
		ptSize += l
	}

	// Layout: 16 system blocks, PVD, terminator, L table, M
	// table, directory extents, continuation areas, file data.
	sector := uint32(18)
	lTableLoc := sector
	sector += uint32((ptSize + blockSize - 1) / blockSize)
	mTableLoc := sector
	sector += uint32((ptSize + blockSize - 1) / blockSize)
	for _, d := range dirs {
		d.extent = sector
		sector += d.size / blockSize
	}
	for _, d := range dirs {
		if d.ceSize > 0 {
			d.ceExtent = sector
			sector += d.ceSize / blockSize
		}
	}
	var dataFiles []*node
	for _, d := range dirs {
		for _, c := range d.children {
			if !c.isDir {
				c.extent = sector
				sector += (c.size + blockSize - 1) / blockSize
				dataFiles = append(dataFiles, c)
			}
		}
	}
	totalSectors := sector

	// Write.
	if _, err := io.CopyN(w, zeroReader{}, 16*blockSize); err != nil {
		return err
	}
	if err := writePVD(w, volumeID, totalSectors, uint32(ptSize), lTableLoc, mTableLoc, root, now); err != nil {
		return err
	}
	if err := writeTerminator(w); err != nil {
		return err
	}
	if err := writePathTable(w, dirs, binary.LittleEndian); err != nil {
		return err
	}
	if err := padToBlock(w, ptSize); err != nil {
		return err
	}
	if err := writePathTable(w, dirs, binary.BigEndian); err != nil {
		return err
	}
	if err := padToBlock(w, ptSize); err != nil {
		return err
	}
	var ceBlobs [][]byte
	for _, d := range dirs {
		recs, ce := buildDirRecords(d, now, d.ceExtent)
		if uint32(len(recs)) != d.size {
			return fmt.Errorf("iso: internal layout error for directory %q", d.name)
		}
		if _, err := w.Write(recs); err != nil {
			return err
		}
		ceBlobs = append(ceBlobs, ce)
	}
	for i, d := range dirs {
		if d.ceSize == 0 {
			continue
		}
		ce := ceBlobs[i]
		if _, err := w.Write(ce); err != nil {
			return err
		}
		if pad := int(d.ceSize) - len(ce); pad > 0 {
			if _, err := io.CopyN(w, zeroReader{}, int64(pad)); err != nil {
				return err
			}
		}
	}
	for _, f := range dataFiles {
		if err := writeFileData(w, f); err != nil {
			return err
		}
	}
	return nil
}

func parentPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// recordKey is the sort key for directory records: the ISO
// identifier, with the file version suffix for files.
func recordKey(n *node) string {
	if n.isDir {
		return n.isoName
	}
	return n.isoName + ";1"
}

// mangleName converts a real name to an ISO 9660 identifier
// (d-characters only, at most 30 bytes for files including the
// extension separator, 31 for directories) and marks it used.
func mangleName(name string, isDir bool, used map[string]bool) string {
	up := strings.ToUpper(name)
	var stem, ext string
	if !isDir {
		if i := strings.LastIndex(up, "."); i > 0 {
			stem, ext = up[:i], up[i+1:]
		} else {
			stem = up
		}
	} else {
		stem = up
	}
	stem = dchars(stem)
	ext = dchars(ext)
	if len(ext) > 3 {
		ext = ext[:3]
	}
	limit := 30
	if isDir {
		limit = 31
	}
	join := func(stem string) string {
		s := stem
		if ext != "" {
			if maxStem := limit - len(ext) - 1; len(s) > maxStem {
				s = s[:maxStem]
			}
			s += "." + ext
		} else if len(s) > limit {
			s = s[:limit]
		}
		if s == "" {
			s = "_"
		}
		return s
	}
	out := join(stem)
	for i := 1; used[out]; i++ {
		suffix := fmt.Sprintf("_%d", i)
		maxStem := limit - len(suffix)
		if ext != "" {
			maxStem -= len(ext) + 1
		}
		s := stem
		if len(s) > maxStem {
			s = s[:maxStem]
		}
		out = join(s + suffix)
	}
	used[out] = true
	return out
}

func dchars(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func pathTableName(d *node) []byte {
	if d.parent == nil {
		return []byte{0}
	}
	return []byte(d.isoName)
}

func modTimeOf(n *node, now time.Time) time.Time {
	if n.entry != nil && !n.entry.ModTime.IsZero() {
		return n.entry.ModTime
	}
	return now
}

func modeOf(n *node) uint32 {
	if n.entry != nil && n.entry.Mode != 0 {
		if n.isDir {
			return 0o40000 | uint32(n.entry.Mode.Perm())
		}
		return 0o100000 | uint32(n.entry.Mode.Perm())
	}
	if n.isDir {
		return 0o40755
	}
	return 0o100644
}

// ---------- Rock Ridge system use entries ----------

func suspNM(name string) []byte {
	var out []byte
	rest := []byte(name)
	for {
		chunk := rest
		cont := byte(0)
		if len(rest) > 250 {
			chunk = rest[:250]
			cont = 1
		}
		e := make([]byte, 5+len(chunk))
		copy(e, "NM")
		e[2] = byte(len(e))
		e[3] = 1
		e[4] = cont
		copy(e[5:], chunk)
		out = append(out, e...)
		if cont == 0 {
			return out
		}
		rest = rest[250:]
	}
}

func suspPX(mode uint32) []byte {
	e := make([]byte, 44)
	copy(e, "PX")
	e[2] = 44
	e[3] = 1
	both32(e[4:], mode)
	both32(e[12:], 1) // links
	both32(e[20:], 0) // uid
	both32(e[28:], 0) // gid
	both32(e[36:], 0) // serial
	return e
}

func suspTF(t time.Time) []byte {
	e := make([]byte, 12)
	copy(e, "TF")
	e[2] = 12
	e[3] = 1
	e[4] = 0x02 // modification time only, 7-byte form
	copy(e[5:], recordDate(t))
	return e
}

func suspSP() []byte {
	return []byte{'S', 'P', 7, 1, 0xBE, 0xEF, 0}
}

func suspER() []byte {
	id := "RRIP_1991A"
	desc := "THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS"
	e := make([]byte, 8+len(id)+len(desc))
	copy(e, "ER")
	e[2] = byte(len(e))
	e[3] = 1
	e[4] = byte(len(id))
	e[5] = byte(len(desc))
	e[6] = 0
	e[7] = 1
	copy(e[8:], id)
	copy(e[8+len(id):], desc)
	return e
}

func suspCE(extent, offset, length uint32) []byte {
	e := make([]byte, 28)
	copy(e, "CE")
	e[2] = 28
	e[3] = 1
	both32(e[4:], extent)
	both32(e[12:], offset)
	both32(e[20:], length)
	return e
}

// suspSplit builds the system use entries for one record. When
// they do not fit a 255-byte directory record (long NM entries),
// the NM entries move to the continuation area: the record keeps
// PX, TF and a CE entry, and the NM bytes are returned as ce.
func suspSplit(n *node, self bool, rootDot bool, now time.Time, recordOverhead int) (inRecord, ce []byte) {
	var head []byte
	if rootDot {
		head = append(head, suspSP()...)
		head = append(head, suspER()...)
	}
	tail := append(suspPX(modeOf(n)), suspTF(modTimeOf(n, now))...)
	if self {
		return append(head, tail...), nil
	}
	nm := suspNM(n.name)
	if recordOverhead+len(head)+len(nm)+len(tail) <= 254 {
		out := append(head, nm...)
		return append(out, tail...), nil
	}
	out := append(head, tail...)
	out = append(out, make([]byte, 28)...) // CE placeholder, patched by caller
	return out, nm
}

// ---------- directory records ----------

// dirRecord assembles one directory record. susp must already be
// at its final length; the record is padded to an even length.
func dirRecord(extent, size uint32, t time.Time, isDir bool, name []byte, susp []byte) []byte {
	l := 33 + len(name) + len(susp)
	if len(name)%2 == 0 {
		l++
	}
	if l%2 == 1 {
		l++
	}
	rec := make([]byte, l)
	rec[0] = byte(l)
	both32(rec[2:], extent)
	both32(rec[10:], size)
	copy(rec[18:], recordDate(t))
	if isDir {
		rec[25] = 2
	}
	both16(rec[28:], 1)
	rec[32] = byte(len(name))
	copy(rec[33:], name)
	off := 33 + len(name)
	if len(name)%2 == 0 {
		off++
	}
	copy(rec[off:], susp)
	return rec
}

// buildDirRecords renders one directory's record area (padded to
// a whole number of blocks) plus its continuation area content.
// ceExtent is the block the continuation area will live at; its
// value does not affect any length, so the measuring pass may
// pass 0.
func buildDirRecords(d *node, now time.Time, ceExtent uint32) (recs, ce []byte) {
	appendRec := func(rec []byte) {
		// Records never cross a block boundary.
		if off := len(recs) % blockSize; off+len(rec) > blockSize {
			recs = append(recs, make([]byte, blockSize-off)...)
		}
		recs = append(recs, rec...)
	}
	mkRecord := func(target *node, name []byte, self bool, rootDot bool) {
		overhead := 33 + len(name)
		if len(name)%2 == 0 {
			overhead++
		}
		inRec, cePart := suspSplit(target, self, rootDot, now, overhead)
		if cePart != nil {
			copy(inRec[len(inRec)-28:], suspCE(ceExtent, uint32(len(ce)), uint32(len(cePart))))
			ce = append(ce, cePart...)
		}
		appendRec(dirRecord(target.extent, target.size, modTimeOf(target, now), target.isDir, name, inRec))
	}
	parent := d.parent
	if parent == nil {
		parent = d
	}
	mkRecord(d, []byte{0}, true, d.parent == nil)
	mkRecord(parent, []byte{1}, true, false)
	for _, c := range d.children {
		var name []byte
		if c.isDir {
			name = []byte(c.isoName)
		} else {
			name = []byte(c.isoName + ";1")
		}
		mkRecord(c, name, false, false)
	}
	if rem := len(recs) % blockSize; rem != 0 {
		recs = append(recs, make([]byte, blockSize-rem)...)
	}
	return recs, ce
}

// ---------- volume descriptors & path table ----------

func writePVD(w io.Writer, volumeID string, totalSectors, ptSize, lLoc, mLoc uint32, root *node, now time.Time) error {
	pvd := make([]byte, blockSize)
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	pvd[6] = 1
	putStr(pvd[8:40], "")
	putStr(pvd[40:72], volumeID)
	both32(pvd[80:], totalSectors)
	both16(pvd[120:], 1)
	both16(pvd[124:], 1)
	both16(pvd[128:], blockSize)
	both32(pvd[132:], ptSize)
	binary.LittleEndian.PutUint32(pvd[140:], lLoc)
	binary.BigEndian.PutUint32(pvd[148:], mLoc)
	copy(pvd[156:], dirRecord(root.extent, root.size, modTimeOf(root, now), true, []byte{0}, nil))
	putStr(pvd[190:318], "")
	putStr(pvd[318:446], "")
	putStr(pvd[446:574], "")
	putStr(pvd[574:702], "G7Z")
	putStr(pvd[702:739], "")
	putStr(pvd[739:776], "")
	putStr(pvd[776:813], "")
	dt := volumeDate(now)
	copy(pvd[813:], dt) // creation
	copy(pvd[830:], dt) // modification
	copy(pvd[847:], "0000000000000000\x00")
	copy(pvd[864:], "0000000000000000\x00")
	pvd[881] = 1
	_, err := w.Write(pvd)
	return err
}

func writeTerminator(w io.Writer) error {
	t := make([]byte, blockSize)
	t[0] = 255
	copy(t[1:], "CD001")
	t[6] = 1
	_, err := w.Write(t)
	return err
}

func writePathTable(w io.Writer, dirs []*node, bo binary.ByteOrder) error {
	for _, d := range dirs {
		name := pathTableName(d)
		rec := make([]byte, 8+len(name)+len(name)%2)
		rec[0] = byte(len(name))
		bo.PutUint32(rec[2:], d.extent)
		parentIdx := uint16(1)
		if d.parent != nil {
			parentIdx = d.parent.index
		}
		bo.PutUint16(rec[6:], parentIdx)
		copy(rec[8:], name)
		if _, err := w.Write(rec); err != nil {
			return err
		}
	}
	return nil
}

func writeFileData(w io.Writer, f *node) error {
	rc, err := f.entry.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	n, err := io.Copy(w, rc)
	if err != nil {
		return err
	}
	if n != int64(f.size) {
		return fmt.Errorf("iso: %s changed size while writing (%d != %d)", f.entry.Name, n, f.size)
	}
	if rem := int(f.size) % blockSize; rem != 0 {
		_, err = io.CopyN(w, zeroReader{}, int64(blockSize-rem))
	}
	return err
}

func padToBlock(w io.Writer, size int) error {
	if rem := size % blockSize; rem != 0 {
		_, err := io.CopyN(w, zeroReader{}, int64(blockSize-rem))
		return err
	}
	return nil
}

// ---------- low-level helpers ----------

func both16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
	binary.BigEndian.PutUint16(b[2:], v)
}

func both32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
	binary.BigEndian.PutUint32(b[4:], v)
}

func putStr(b []byte, s string) {
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
}

// recordDate is the 7-byte directory record timestamp.
func recordDate(t time.Time) []byte {
	_, off := t.Zone()
	return []byte{
		byte(t.Year() - 1900),
		byte(t.Month()),
		byte(t.Day()),
		byte(t.Hour()),
		byte(t.Minute()),
		byte(t.Second()),
		byte(int8(off / 900)),
	}
}

// volumeDate is the 17-byte volume descriptor timestamp: sixteen
// ASCII digits and a signed timezone byte (15-minute units).
func volumeDate(t time.Time) []byte {
	_, off := t.Zone()
	s := fmt.Sprintf("%04d%02d%02d%02d%02d%02d%02d",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(),
		t.Nanosecond()/10000000)
	return append([]byte(s), byte(int8(off/900)))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
