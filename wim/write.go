package wim

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

// Writer builds a single-image WIM file. Level 0 stores resources,
// levels above 0 compress them with XPRESS.
type Writer struct {
	f     *os.File
	level int
	off   int64

	entries []*lookupEntry // file resources, in write order
	byHash  map[[20]byte]*lookupEntry

	root     *dnode
	fileCnt  int
	dirCnt   int // excluding the root
	totalLen int64
}

type dnode struct {
	name     string
	attrs    uint32
	wtime    uint64
	hash     [20]byte
	isDir    bool
	children []*dnode
	byName   map[string]*dnode
	subPos   int // offset of the suboff field within the metadata buffer, for patching
}

func timeToFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()/100) + 116444736000000000
}

// NewWriter starts a WIM file on f (which must be empty).
func NewWriter(f *os.File, level int) *Writer {
	return &Writer{
		f:      f,
		level:  level,
		off:    headerSize,
		byHash: map[[20]byte]*lookupEntry{},
		root:   &dnode{isDir: true, attrs: 0x10, byName: map[string]*dnode{}},
	}
}

// Add registers one file or directory. Content is the file's full
// contents (ignored for directories).
func (w *Writer) Add(name string, mode fs.FileMode, modTime time.Time, isDir bool, content []byte) error {
	node := w.ensurePath(name, isDir)
	node.wtime = timeToFiletime(modTime)
	node.attrs = 0x20
	if isDir {
		node.attrs = 0x10
	}
	if mode&0200 == 0 {
		node.attrs |= 0x1 // read-only
	}
	if isDir {
		return nil
	}
	if len(content) == 0 {
		node.hash = zeroHash
		return nil
	}
	hash := sha1.Sum(content)
	node.hash = hash
	if _, dup := w.byHash[hash]; dup {
		w.byHash[hash].refcnt++
		return nil
	}
	raw, compressed := compressResource(content, w.level)
	e := &lookupEntry{part: 1, refcnt: 1, hash: hash}
	e.size = int64(len(raw))
	e.origSize = int64(len(content))
	e.offset = w.off
	if compressed {
		e.flags = reshdrFlagCompressed
	}
	if _, err := w.f.WriteAt(raw, w.off); err != nil {
		return err
	}
	w.off += e.size
	w.entries = append(w.entries, e)
	w.byHash[hash] = e
	return nil
}

func (w *Writer) ensurePath(name string, isDir bool) *dnode {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	cur := w.root
	for i, p := range parts {
		last := i == len(parts)-1
		child, ok := cur.byName[p]
		if !ok {
			child = &dnode{name: p, isDir: !last || isDir, attrs: 0x10, byName: map[string]*dnode{}}
			if last && !isDir {
				child.attrs = 0x20
			}
			cur.byName[p] = child
			cur.children = append(cur.children, child)
			if child.isDir && child != w.root {
				w.dirCnt++
			} else {
				w.fileCnt++
			}
		}
		cur = child
	}
	return cur
}

// compressResource applies WIM chunk compression (32 KiB chunks,
// chunk table of u32 offsets relative to the end of the table).
// It returns the stored form and whether compression was used; a
// resource that does not shrink is returned raw.
func compressResource(data []byte, level int) ([]byte, bool) {
	if level <= 0 || len(data) == 0 {
		return data, false
	}
	nchunks := (len(data) + chunkSize - 1) / chunkSize
	chunks := make([][]byte, nchunks)
	allRaw := true
	total := int64(nchunks-1) * 4
	for i := 0; i < nchunks; i++ {
		lo, hi := i*chunkSize, (i+1)*chunkSize
		if hi > len(data) {
			hi = len(data)
		}
		chunk := data[lo:hi]
		c, err := xpressCompressChunk(chunk)
		if err == nil && len(c) < len(chunk) {
			chunks[i] = c
			allRaw = false
		} else {
			chunks[i] = chunk
		}
		total += int64(len(chunks[i]))
	}
	if allRaw || total >= int64(len(data)) {
		return data, false
	}
	out := make([]byte, 0, total)
	off := int64(0)
	for i := 1; i < nchunks; i++ {
		off += int64(len(chunks[i-1]))
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(off))
		out = append(out, b[:]...)
	}
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out, true
}

// Close writes the metadata resource, lookup table, XML data and
// header, completing the WIM file.
func (w *Writer) Close() error {
	// totalLen is the sum of file sizes for the XML block; compute
	// it from the dentries directly.
	w.totalLen = 0
	var sum func(n *dnode)
	sum = func(n *dnode) {
		for _, c := range n.children {
			if c.isDir {
				sum(c)
			} else if le, ok := w.byHash[c.hash]; ok {
				w.totalLen += le.origSize
			}
		}
	}
	sortChildren(w.root)
	sum(w.root)

	meta := w.buildMetadata()
	metaEntry := &lookupEntry{part: 1, refcnt: 1, hash: sha1.Sum(meta)}
	metaEntry.size = int64(len(meta))
	metaEntry.origSize = metaEntry.size
	metaEntry.offset = w.off
	metaEntry.flags = reshdrFlagMetadata
	if _, err := w.f.WriteAt(meta, w.off); err != nil {
		return err
	}
	w.off += metaEntry.size

	tableOff := w.off
	all := append(append([]*lookupEntry{}, w.entries...), metaEntry)
	var table []byte
	for _, e := range all {
		b := make([]byte, lookupSize)
		copy(b, e.reshdr.marshal())
		binary.LittleEndian.PutUint16(b[24:], e.part)
		binary.LittleEndian.PutUint32(b[26:], e.refcnt)
		copy(b[30:], e.hash[:])
		table = append(table, b...)
	}
	if _, err := w.f.WriteAt(table, tableOff); err != nil {
		return err
	}
	w.off += int64(len(table))

	xmlOff := w.off
	xml := buildXML(xmlOff, w.dirCnt, w.fileCnt, w.totalLen, time.Now())
	if _, err := w.f.WriteAt(xml, xmlOff); err != nil {
		return err
	}
	w.off += int64(len(xml))

	hdr := make([]byte, headerSize)
	copy(hdr, "MSWIM\x00\x00\x00")
	binary.LittleEndian.PutUint32(hdr[8:], headerSize)
	binary.LittleEndian.PutUint32(hdr[12:], 0x10D00)
	flags := uint32(0x80) // RP_FIX, as written by other tools
	chunk := uint32(0)
	if w.level > 0 {
		flags |= flagHeaderCompression | flagHeaderCompressXP
		chunk = chunkSize
	}
	binary.LittleEndian.PutUint32(hdr[16:], flags)
	binary.LittleEndian.PutUint32(hdr[20:], chunk)
	if _, err := rand.Read(hdr[24:40]); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(hdr[40:], 1)
	binary.LittleEndian.PutUint16(hdr[42:], 1)
	binary.LittleEndian.PutUint32(hdr[44:], 1)
	ot := reshdr{size: int64(len(table)), offset: tableOff, origSize: int64(len(table)), flags: reshdrFlagMetadata}
	copy(hdr[48:], ot.marshal())
	xd := reshdr{size: int64(len(xml)), offset: xmlOff, origSize: int64(len(xml)), flags: reshdrFlagMetadata}
	copy(hdr[72:], xd.marshal())
	_, err := w.f.WriteAt(hdr, 0)
	return err
}

func sortChildren(n *dnode) {
	sort.Slice(n.children, func(i, j int) bool { return n.children[i].name < n.children[j].name })
	for _, c := range n.children {
		sortChildren(c)
	}
}

// buildMetadata serializes the security block and dentry tree.
// Layout: security block, root dentry, an 8-byte end tag, then for
// each directory (in the order its dentry was written) its child
// list followed by an 8-byte end tag.
func (w *Writer) buildMetadata() []byte {
	buf := make([]byte, securitySize)
	binary.LittleEndian.PutUint32(buf, securitySize)
	emit := func(n *dnode) {
		n.subPos = len(buf) + 16
		name16 := utf16Encode(n.name)
		// The name is followed by a 2-byte null terminator inside
		// the entry; the total is then padded to a multiple of 8,
		// plus one more block when it already is one (this matches
		// the layout other writers produce — readers that scan for
		// the terminator fail without it).
		length := dentrySize + len(name16)
		if len(name16) > 0 {
			length += 2
			if length%8 == 0 {
				length += 8
			} else {
				length = (length + 7) &^ 7
			}
		} else {
			length = (length + 7) &^ 7
		}
		b := make([]byte, length)
		binary.LittleEndian.PutUint64(b, uint64(length))
		binary.LittleEndian.PutUint32(b[8:], n.attrs)
		binary.LittleEndian.PutUint32(b[12:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint64(b[40:], n.wtime)
		binary.LittleEndian.PutUint64(b[48:], n.wtime)
		binary.LittleEndian.PutUint64(b[56:], n.wtime)
		copy(b[64:84], n.hash[:])
		binary.LittleEndian.PutUint16(b[100:], uint16(len(name16)))
		copy(b[dentrySize:], name16)
		buf = append(buf, b...)
	}
	var writeList func(n *dnode)
	writeList = func(n *dnode) {
		// Every directory gets a child list, even an empty one
		// (just the end tag): some readers treat a zero
		// subdirectory offset as "not a directory".
		// Patch this directory's subdirectory offset first.
		binary.LittleEndian.PutUint64(buf[n.subPos:], uint64(len(buf)))
		for _, c := range n.children {
			emit(c)
		}
		buf = append(buf, make([]byte, 8)...)
		for _, c := range n.children {
			if c.isDir {
				writeList(c)
			}
		}
	}
	emit(w.root)
	buf = append(buf, make([]byte, 8)...)
	writeList(w.root)
	return buf
}

func buildXML(xmlOffset int64, dirCount, fileCount int, totalBytes int64, now time.Time) []byte {
	ft := timeToFiletime(now)
	s := fmt.Sprintf("<WIM><TOTALBYTES>%d</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>1</NAME>"+
		"<DIRCOUNT>%d</DIRCOUNT><FILECOUNT>%d</FILECOUNT><TOTALBYTES>%d</TOTALBYTES>"+
		"<CREATIONTIME><HIGHPART>0x%08X</HIGHPART><LOWPART>0x%08X</LOWPART></CREATIONTIME>"+
		"<LASTMODIFICATIONTIME><HIGHPART>0x%08X</HIGHPART><LOWPART>0x%08X</LOWPART></LASTMODIFICATIONTIME>"+
		"</IMAGE></WIM>",
		xmlOffset, dirCount, fileCount, totalBytes,
		ft>>32, ft&0xFFFFFFFF, ft>>32, ft&0xFFFFFFFF)
	body := utf16Encode(s)
	out := make([]byte, 0, len(body)+2)
	out = append(out, 0xFF, 0xFE) // UTF-16LE BOM
	return append(out, body...)
}
