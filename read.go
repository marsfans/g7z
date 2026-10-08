package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bodgit/sevenzip"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/nwaples/rardecode/v2"
	"github.com/ulikunitz/xz"
	yzip "github.com/yeka/zip"
)

// Entry 归档中的一个条目
type Entry struct {
	Name      string
	Size      int64 // -1 表示未知
	Packed    int64 // -1 表示未知
	ModTime   time.Time
	Mode      fs.FileMode
	IsDir     bool
	Link      string
	HardLink  bool
	Encrypted bool
	CRC       uint32
	HasCRC    bool
}

// WalkFunc 对每个条目调用；open 只能在回调内调用一次
type WalkFunc func(e *Entry, open func() (io.ReadCloser, error)) error

var errNeedPassword = errors.New("需要密码")

func init() {
	// zip 内的 zstd(93) / xz(95) 方法
	yzip.RegisterDecompressor(93, func(r io.Reader) io.ReadCloser {
		d, err := zstd.NewReader(r)
		if err != nil {
			return io.NopCloser(errReader{err})
		}
		return d.IOReadCloser()
	})
	yzip.RegisterDecompressor(95, func(r io.Reader) io.ReadCloser {
		d, err := xz.NewReader(r)
		if err != nil {
			return io.NopCloser(errReader{err})
		}
		return io.NopCloser(d)
	})
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func walkArchive(path string, fm *Format, password string, fn WalkFunc) error {
	switch {
	case fm.Name == "7z":
		return walk7z(path, password, fn)
	case fm.Name == "zip":
		return walkZip(path, password, fn)
	case fm.Name == "rar":
		return walkRar(path, password, fn)
	case fm.Archive:
		return walkTar(path, fm.Codec, fn)
	default:
		return walkSingle(path, fm, fn)
	}
}

func walk7z(path, password string, fn WalkFunc) error {
	r, err := sevenzip.OpenReaderWithPassword(path, password)
	if err != nil {
		return wrapPwErr(err, password)
	}
	defer r.Close()
	for _, f := range r.File {
		info := f.FileInfo()
		e := &Entry{Name: f.Name, Size: int64(f.UncompressedSize), Packed: -1, ModTime: f.Modified, Mode: info.Mode(), IsDir: info.IsDir(), CRC: f.CRC32, HasCRC: f.CRC32 != 0}
		f := f
		if err := fn(e, func() (io.ReadCloser, error) { return f.Open() }); err != nil {
			return wrapPwErr(err, password)
		}
	}
	return nil
}

func wrapPwErr(err error, password string) error {
	if err == nil {
		return nil
	}
	if password == "" && isPwError(err) {
		return errNeedPassword
	}
	s := strings.ToLower(err.Error())
	if password == "" && (strings.Contains(s, "password") || strings.Contains(s, "encrypt")) {
		return errNeedPassword
	}
	if password != "" && (isPwError(err) || strings.Contains(s, "checksum") || strings.Contains(s, "password") || strings.Contains(s, "crc") || strings.Contains(s, "corrupt") || strings.Contains(s, "invalid") || strings.Contains(s, "authentication") || strings.Contains(s, "unexpected") || strings.Contains(s, "lzma")) {
		return fmt.Errorf("%w（密码可能错误）", err)
	}
	return err
}

func walkZip(path, password string, fn WalkFunc) error {
	r, err := yzip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		info := f.FileInfo()
		e := &Entry{Name: f.Name, Size: int64(f.UncompressedSize64), Packed: int64(f.CompressedSize64), ModTime: f.ModTime(), Mode: info.Mode(), IsDir: info.IsDir(), Encrypted: f.IsEncrypted(), CRC: f.CRC32, HasCRC: true}
		f := f
		err := fn(e, func() (io.ReadCloser, error) {
			if f.IsEncrypted() {
				if password == "" {
					return nil, errNeedPassword
				}
				f.SetPassword(password)
			}
			return f.Open()
		})
		if err != nil {
			return wrapPwErr(err, password)
		}
	}
	return nil
}

func walkRar(path, password string, fn WalkFunc) error {
	var opts []rardecode.Option
	if password != "" {
		opts = append(opts, rardecode.Password(password))
	}
	r, err := rardecode.OpenReader(path, opts...)
	if err != nil {
		return wrapPwErr(err, password)
	}
	defer r.Close()
	for {
		h, err := r.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return wrapPwErr(err, password)
		}
		e := &Entry{Name: h.Name, Size: h.UnPackedSize, Packed: h.PackedSize, ModTime: h.ModificationTime, Mode: h.Mode(), IsDir: h.IsDir, Encrypted: h.Encrypted}
		if h.UnKnownSize {
			e.Size = -1
		}
		if err := fn(e, func() (io.ReadCloser, error) { return io.NopCloser(r), nil }); err != nil {
			return wrapPwErr(err, password)
		}
	}
}

func walkTar(path, codec string, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rc, err := newDecompressor(codec, f)
	if err != nil {
		return err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		info := h.FileInfo()
		e := &Entry{Name: h.Name, Size: h.Size, Packed: -1, ModTime: h.ModTime, Mode: info.Mode(), IsDir: h.Typeflag == tar.TypeDir}
		switch h.Typeflag {
		case tar.TypeSymlink:
			e.Link = h.Linkname
		case tar.TypeLink:
			e.Link = h.Linkname
			e.HardLink = true
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		case tar.TypeXGlobalHeader:
			continue
		default:
			continue
		}
		if err := fn(e, func() (io.ReadCloser, error) { return io.NopCloser(tr), nil }); err != nil {
			return err
		}
	}
}

func walkSingle(path string, fm *Format, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, _ := f.Stat()
	rc, err := newDecompressor(fm.Codec, f)
	if err != nil {
		return err
	}
	defer rc.Close()
	name := filepath.Base(path)
	for _, ext := range fm.Exts {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			name = name[:len(name)-len(ext)]
			break
		}
	}
	mt := st.ModTime()
	if gz, ok := rc.(*gzip.Reader); ok {
		if gz.Name != "" {
			name = filepath.Base(gz.Name)
		}
		if !gz.ModTime.IsZero() {
			mt = gz.ModTime
		}
	}
	if name == "" {
		name = "data"
	}
	e := &Entry{Name: name, Size: -1, Packed: st.Size(), ModTime: mt, Mode: 0o644}
	return fn(e, func() (io.ReadCloser, error) { return io.NopCloser(rc), nil })
}
