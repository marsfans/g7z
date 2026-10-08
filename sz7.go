package main

// 7z 归档写入器：LZMA2（或存储）编码，可选 7zAES(AES-256 + SHA-256) 加密。
// 文件按固实块分组为多个 folder，并行压缩到临时文件后按顺序拼接。

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/ulikunitz/xz/lzma"
)

type SZOptions struct {
	Level      int // 0 = 仅存储
	Password   string
	SolidBlock int64 // 每个固实块的最大原始字节数
	Threads    int
}

type szFolder struct {
	files      []*InputFile
	unpackSize int64
	tmp        *os.File
	packSize   int64
	codedSize  int64 // AES 之前（LZMA2 输出）的大小
	iv         []byte
	crcs       []uint32
	err        error
}

func write7z(out string, files []*InputFile, opt SZOptions, prog *Progress) error {
	if opt.Threads < 1 {
		opt.Threads = 1
	}
	if opt.SolidBlock <= 0 {
		opt.SolidBlock = 64 << 20
	}
	// 分块
	var folders []*szFolder
	var cur *szFolder
	for _, f := range files {
		if f.IsDir || f.Size == 0 {
			continue
		}
		if cur == nil || cur.unpackSize >= opt.SolidBlock {
			cur = &szFolder{}
			folders = append(folders, cur)
		}
		cur.files = append(cur.files, f)
		cur.unpackSize += f.Size
	}

	var key []byte
	if opt.Password != "" {
		key = sz7Key(opt.Password, nil, 19)
	}

	// 并行压缩
	sem := make(chan struct{}, opt.Threads)
	var wg sync.WaitGroup
	for _, fd := range folders {
		wg.Add(1)
		sem <- struct{}{}
		go func(fd *szFolder) {
			defer wg.Done()
			defer func() { <-sem }()
			fd.err = compressFolder(fd, opt, key, prog)
		}(fd)
	}
	wg.Wait()
	defer func() {
		for _, fd := range folders {
			if fd.tmp != nil {
				fd.tmp.Close()
				os.Remove(fd.tmp.Name())
			}
		}
	}()
	for _, fd := range folders {
		if fd.err != nil {
			return fd.err
		}
	}

	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	if _, err := o.Write(make([]byte, 32)); err != nil {
		return err
	}
	var packTotal int64
	for _, fd := range folders {
		if _, err := fd.tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		n, err := io.Copy(o, fd.tmp)
		if err != nil {
			return err
		}
		packTotal += n
	}
	hdr := build7zHeader(files, folders, opt)
	if _, err := o.Write(hdr); err != nil {
		return err
	}
	// 签名头
	sig := make([]byte, 32)
	copy(sig, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4})
	binary.LittleEndian.PutUint64(sig[12:], uint64(packTotal))
	binary.LittleEndian.PutUint64(sig[20:], uint64(len(hdr)))
	binary.LittleEndian.PutUint32(sig[28:], crc32.ChecksumIEEE(hdr))
	binary.LittleEndian.PutUint32(sig[8:], crc32.ChecksumIEEE(sig[12:32]))
	if _, err := o.WriteAt(sig, 0); err != nil {
		return err
	}
	return o.Close()
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func compressFolder(fd *szFolder, opt SZOptions, key []byte, prog *Progress) error {
	tmp, err := os.CreateTemp("", "g7z-*.part")
	if err != nil {
		return err
	}
	fd.tmp = tmp
	packCounter := &countWriter{w: tmp}
	var sink io.Writer = packCounter
	var aesW *cbcWriter
	if key != nil {
		fd.iv = make([]byte, 16)
		if _, err := rand.Read(fd.iv); err != nil {
			return err
		}
		aesW, err = newCBCWriter(packCounter, key, fd.iv)
		if err != nil {
			return err
		}
		sink = aesW
	}
	codedCounter := &countWriter{w: sink}
	var enc io.Writer = codedCounter
	var lz *lzma.Writer2
	if opt.Level > 0 {
		cfg := lzma.Writer2Config{DictCap: dictForLevel(opt.Level)}
		if int64(cfg.DictCap) > fd.unpackSize && fd.unpackSize >= lzma.MinDictCap {
			cfg.DictCap = int(fd.unpackSize)
		}
		lz, err = cfg.NewWriter2(codedCounter)
		if err != nil {
			return err
		}
		enc = lz
	}
	buf := make([]byte, 1<<20)
	for _, f := range fd.files {
		prog.SetCurrent(f.Name)
		src, err := os.Open(f.Path)
		if err != nil {
			return err
		}
		h := crc32.NewIEEE()
		n, err := io.CopyBuffer(io.MultiWriter(enc, h), io.TeeReader(src, prog), buf)
		src.Close()
		if err != nil {
			return err
		}
		if n != f.Size {
			return errors.New("文件在压缩过程中被修改: " + f.Path)
		}
		fd.crcs = append(fd.crcs, h.Sum32())
	}
	if lz != nil {
		if err := lz.Close(); err != nil {
			return err
		}
	}
	if aesW != nil {
		if err := aesW.Close(); err != nil {
			return err
		}
	}
	fd.codedSize = codedCounter.n
	fd.packSize = packCounter.n
	return nil
}

// ---------- 7zAES ----------

func sz7Key(password string, salt []byte, cyclesPower int) []byte {
	pw := utf16.Encode([]rune(password))
	pb := make([]byte, len(pw)*2)
	for i, c := range pw {
		binary.LittleEndian.PutUint16(pb[i*2:], c)
	}
	h := sha256.New()
	var ctr [8]byte
	buf := make([]byte, 0, (len(salt)+len(pb)+8)*1024)
	rounds := uint64(1) << cyclesPower
	for i := uint64(0); i < rounds; i++ {
		binary.LittleEndian.PutUint64(ctr[:], i)
		buf = append(buf, salt...)
		buf = append(buf, pb...)
		buf = append(buf, ctr[:]...)
		if len(buf) >= cap(buf)-(len(salt)+len(pb)+8) {
			h.Write(buf)
			buf = buf[:0]
		}
	}
	h.Write(buf)
	return h.Sum(nil)
}

type cbcWriter struct {
	w    io.Writer
	mode cipher.BlockMode
	buf  []byte
}

func newCBCWriter(w io.Writer, key, iv []byte) (*cbcWriter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cbcWriter{w: w, mode: cipher.NewCBCEncrypter(b, iv)}, nil
}

func (c *cbcWriter) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	full := len(c.buf) / 16 * 16
	if full > 0 {
		out := make([]byte, full)
		c.mode.CryptBlocks(out, c.buf[:full])
		if _, err := c.w.Write(out); err != nil {
			return 0, err
		}
		c.buf = append(c.buf[:0], c.buf[full:]...)
	}
	return len(p), nil
}

func (c *cbcWriter) Close() error {
	if len(c.buf) > 0 {
		blk := make([]byte, 16)
		copy(blk, c.buf)
		c.mode.CryptBlocks(blk, blk)
		c.buf = nil
		_, err := c.w.Write(blk)
		return err
	}
	return nil
}

// ---------- 头部编码 ----------

type hbuf struct{ bytes.Buffer }

func (b *hbuf) num(v uint64) {
	first := byte(0)
	mask := byte(0x80)
	i := 0
	for ; i < 8; i++ {
		if v < (uint64(1) << (7 * (i + 1))) {
			first |= byte(v >> (8 * i))
			break
		}
		first |= mask
		mask >>= 1
	}
	b.WriteByte(first)
	for ; i > 0; i-- {
		b.WriteByte(byte(v))
		v >>= 8
	}
}

func bitVector(bits []bool) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, v := range bits {
		if v {
			out[i/8] |= 0x80 >> (i % 8)
		}
	}
	return out
}

func lzma2DictProp(dict int) byte {
	for p := 0; p < 40; p++ {
		size := int64(2|(p&1)) << (p/2 + 11)
		if size >= int64(dict) {
			return byte(p)
		}
	}
	return 40
}

func fileTime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100 + 116444736000000000)
}

func build7zHeader(files []*InputFile, folders []*szFolder, opt SZOptions) []byte {
	b := &hbuf{}
	b.WriteByte(0x01) // kHeader
	if len(folders) > 0 {
		b.WriteByte(0x04) // kMainStreamsInfo
		// PackInfo
		b.WriteByte(0x06)
		b.num(0)
		b.num(uint64(len(folders)))
		b.WriteByte(0x09)
		for _, fd := range folders {
			b.num(uint64(fd.packSize))
		}
		b.WriteByte(0x00)
		// UnpackInfo
		b.WriteByte(0x07)
		b.WriteByte(0x0B)
		b.num(uint64(len(folders)))
		b.WriteByte(0x00) // external = 0
		for _, fd := range folders {
			writeFolder(b, fd, opt)
		}
		b.WriteByte(0x0C)
		for _, fd := range folders {
			if opt.Password != "" {
				b.num(uint64(fd.codedSize))
			}
			b.num(uint64(fd.unpackSize))
		}
		b.WriteByte(0x00)
		// SubStreamsInfo
		b.WriteByte(0x08)
		b.WriteByte(0x0D)
		for _, fd := range folders {
			b.num(uint64(len(fd.files)))
		}
		b.WriteByte(0x09)
		for _, fd := range folders {
			for i := 0; i < len(fd.files)-1; i++ {
				b.num(uint64(fd.files[i].Size))
			}
		}
		b.WriteByte(0x0A)
		b.WriteByte(0x01) // all defined
		var crc [4]byte
		for _, fd := range folders {
			for _, c := range fd.crcs {
				binary.LittleEndian.PutUint32(crc[:], c)
				b.Write(crc[:])
			}
		}
		b.WriteByte(0x00)
		b.WriteByte(0x00) // end StreamsInfo
	}
	if len(files) > 0 {
		b.WriteByte(0x05) // kFilesInfo
		b.num(uint64(len(files)))
		empty := make([]bool, len(files))
		var emptyFile []bool
		anyEmpty := false
		for i, f := range files {
			if f.IsDir || f.Size == 0 {
				empty[i] = true
				anyEmpty = true
				emptyFile = append(emptyFile, !f.IsDir)
			}
		}
		if anyEmpty {
			v := bitVector(empty)
			b.WriteByte(0x0E)
			b.num(uint64(len(v)))
			b.Write(v)
			hasEF := false
			for _, e := range emptyFile {
				hasEF = hasEF || e
			}
			if hasEF {
				v := bitVector(emptyFile)
				b.WriteByte(0x0F)
				b.num(uint64(len(v)))
				b.Write(v)
			}
		}
		// 名称
		nb := &bytes.Buffer{}
		nb.WriteByte(0) // external
		for _, f := range files {
			for _, c := range utf16.Encode([]rune(f.Name)) {
				nb.WriteByte(byte(c))
				nb.WriteByte(byte(c >> 8))
			}
			nb.Write([]byte{0, 0})
		}
		b.WriteByte(0x11)
		b.num(uint64(nb.Len()))
		b.Write(nb.Bytes())
		// 修改时间
		b.WriteByte(0x14)
		b.num(uint64(2 + 8*len(files)))
		b.WriteByte(1)
		b.WriteByte(0)
		var t8 [8]byte
		for _, f := range files {
			binary.LittleEndian.PutUint64(t8[:], fileTime(f.ModTime))
			b.Write(t8[:])
		}
		// 属性（Windows 属性 + Unix 权限扩展）
		b.WriteByte(0x15)
		b.num(uint64(2 + 4*len(files)))
		b.WriteByte(1)
		b.WriteByte(0)
		var a4 [4]byte
		for _, f := range files {
			perm := uint32(f.Mode.Perm())
			var attr uint32
			if f.IsDir {
				attr = 0x10 | 0x8000 | (0o040000|perm)<<16
			} else {
				attr = 0x20 | 0x8000 | (0o100000|perm)<<16
			}
			binary.LittleEndian.PutUint32(a4[:], attr)
			b.Write(a4[:])
		}
		b.WriteByte(0x00)
	}
	b.WriteByte(0x00)
	return b.Bytes()
}

func writeFolder(b *hbuf, fd *szFolder, opt SZOptions) {
	writeMain := func() {
		if opt.Level == 0 {
			b.WriteByte(0x01) // id size 1, 无属性
			b.WriteByte(0x00) // Copy
			return
		}
		dict := dictForLevel(opt.Level)
		if int64(dict) > fd.unpackSize && fd.unpackSize >= lzma.MinDictCap {
			dict = int(fd.unpackSize)
		}
		b.WriteByte(0x21) // id size 1 + 属性
		b.WriteByte(0x21) // LZMA2
		b.num(1)
		b.WriteByte(lzma2DictProp(dict))
	}
	if opt.Password == "" {
		b.num(1)
		writeMain()
		return
	}
	b.num(2)
	// coder 0: 7zAES
	b.WriteByte(0x24)
	b.Write([]byte{0x06, 0xF1, 0x07, 0x01})
	props := append([]byte{0x40 | 19, 0x0F}, fd.iv...)
	b.num(uint64(len(props)))
	b.Write(props)
	// coder 1: LZMA2 / Copy
	writeMain()
	// bind pair: coder1 输入 <- coder0 输出
	b.num(1)
	b.num(0)
}
