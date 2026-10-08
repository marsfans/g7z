package main

import (
	"archive/tar"
	stdzip "archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	yzip "github.com/yeka/zip"
)

// InputFile 待压缩的一个条目
type InputFile struct {
	Name    string // 归档内路径（/ 分隔）
	Path    string // 磁盘路径
	Size    int64
	ModTime time.Time
	Mode    fs.FileMode
	IsDir   bool
	Link    string // 符号链接目标（仅 tar 保留）
}

type AddOptions struct {
	Format    *Format
	Level     int
	Password  string
	Threads   int
	Solid     int64
	Excludes  []string
	Recursive bool
}

func excluded(name string, pats []string) bool {
	base := path.Base(name)
	for _, p := range pats {
		if ok, _ := path.Match(p, base); ok {
			return true
		}
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// collectInputs 遍历输入路径；目录内容以目录名为前缀存入（与 7z 一致）
func collectInputs(args []string, opt AddOptions, keepLinks bool, skip string) ([]*InputFile, error) {
	var out []*InputFile
	seen := map[string]bool{}
	skipAbs, _ := filepath.Abs(skip)
	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil || len(matches) == 0 {
			matches = []string{arg}
		}
		for _, m := range matches {
			m = filepath.Clean(m)
			base := filepath.Dir(m)
			err := filepath.WalkDir(m, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if abs, _ := filepath.Abs(p); abs == skipAbs || abs == skipAbs+".g7ztmp" {
					return nil
				}
				rel, err := filepath.Rel(base, p)
				if err != nil || strings.HasPrefix(rel, "..") {
					rel = filepath.Base(p)
				}
				name := filepath.ToSlash(rel)
				if name == "." || name == "" {
					return nil
				}
				if excluded(name, opt.Excludes) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if seen[name] {
					return nil
				}
				seen[name] = true
				info, err := os.Lstat(p)
				if err != nil {
					return err
				}
				f := &InputFile{Name: name, Path: p, ModTime: info.ModTime(), Mode: info.Mode()}
				if info.Mode()&fs.ModeSymlink != 0 {
					if keepLinks {
						f.Link, _ = os.Readlink(p)
						out = append(out, f)
						return nil
					}
					st, err := os.Stat(p)
					if err != nil || st.IsDir() {
						logWarn("跳过符号链接 %s", p)
						return nil
					}
					info = st
					f.Mode = st.Mode()
				}
				if info.IsDir() {
					f.IsDir = true
					out = append(out, f)
					if !opt.Recursive && p != m {
						return filepath.SkipDir
					}
					return nil
				}
				if !info.Mode().IsRegular() {
					return nil
				}
				f.Size = info.Size()
				out = append(out, f)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有找到要压缩的文件")
	}
	return out, nil
}

func totalSize(files []*InputFile) (int64, int, int) {
	var n int64
	nf, nd := 0, 0
	for _, f := range files {
		if f.IsDir {
			nd++
		} else {
			nf++
			n += f.Size
		}
	}
	return n, nf, nd
}

func createArchive(out string, files []*InputFile, opt AddOptions, prog *Progress) error {
	fm := opt.Format
	tmpOut := out + ".g7ztmp"
	var err error
	switch {
	case fm.Name == "7z":
		err = write7z(tmpOut, files, SZOptions{Level: opt.Level, Password: opt.Password, SolidBlock: opt.Solid, Threads: opt.Threads}, prog)
	case fm.Name == "zip":
		err = writeZip(tmpOut, files, opt, prog)
	case fm.Archive: // tar.*
		err = writeTar(tmpOut, files, fm.Codec, opt, prog)
	default:
		err = writeSingle(tmpOut, files, fm.Codec, opt, prog)
	}
	if err != nil {
		os.Remove(tmpOut)
		return err
	}
	os.Remove(out)
	return os.Rename(tmpOut, out)
}

func copyFile(w io.Writer, f *InputFile, prog *Progress) error {
	prog.SetCurrent(f.Name)
	src, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer src.Close()
	_, err = io.CopyBuffer(w, io.TeeReader(src, prog), make([]byte, 1<<20))
	return err
}

func writeZip(out string, files []*InputFile, opt AddOptions, prog *Progress) error {
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	if opt.Password != "" {
		zw := yzip.NewWriter(o)
		for _, f := range files {
			fh := &yzip.FileHeader{Name: f.Name, Method: yzip.Deflate}
			fh.SetModTime(f.ModTime)
			fh.SetMode(f.Mode)
			if f.IsDir {
				fh.Name += "/"
				fh.Method = yzip.Store
				if _, err := zw.CreateHeader(fh); err != nil {
					return err
				}
				continue
			}
			if opt.Level == 0 {
				fh.Method = yzip.Store
			}
			fh.SetPassword(opt.Password)
			fh.SetEncryptionMethod(yzip.AES256Encryption)
			w, err := zw.CreateHeader(fh)
			if err != nil {
				return err
			}
			if err := copyFile(w, f, prog); err != nil {
				return err
			}
		}
		if err := zw.Close(); err != nil {
			return err
		}
		return o.Close()
	}
	zw := stdzip.NewWriter(o)
	lvl := opt.Level
	zw.RegisterCompressor(stdzip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, lvl)
	})
	for _, f := range files {
		fh, err := stdzip.FileInfoHeader(fileInfoOf(f))
		if err != nil {
			return err
		}
		fh.Name = f.Name
		if f.IsDir {
			fh.Name += "/"
			fh.Method = stdzip.Store
		} else if opt.Level == 0 {
			fh.Method = stdzip.Store
		} else {
			fh.Method = stdzip.Deflate
		}
		fh.Modified = f.ModTime
		w, err := zw.CreateHeader(fh)
		if err != nil {
			return err
		}
		if !f.IsDir {
			if err := copyFile(w, f, prog); err != nil {
				return err
			}
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return o.Close()
}

type inputInfo struct{ f *InputFile }

func (i inputInfo) Name() string       { return path.Base(i.f.Name) }
func (i inputInfo) Size() int64        { return i.f.Size }
func (i inputInfo) Mode() fs.FileMode  { return i.f.Mode }
func (i inputInfo) ModTime() time.Time { return i.f.ModTime }
func (i inputInfo) IsDir() bool        { return i.f.IsDir }
func (i inputInfo) Sys() any           { return nil }

func fileInfoOf(f *InputFile) fs.FileInfo { return inputInfo{f} }

func writeTar(out string, files []*InputFile, codec string, opt AddOptions, prog *Progress) error {
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	var w io.Writer = o
	var cw io.WriteCloser
	if codec != "" {
		cw, err = newCompressor(codec, o, opt.Level, opt.Threads)
		if err != nil {
			return err
		}
		w = cw
	}
	tw := tar.NewWriter(w)
	for _, f := range files {
		hdr, err := tar.FileInfoHeader(fileInfoOf(f), f.Link)
		if err != nil {
			return err
		}
		hdr.Name = f.Name
		if f.IsDir {
			hdr.Name += "/"
		}
		hdr.Format = tar.FormatPAX
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg {
			if err := copyFile(tw, f, prog); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if cw != nil {
		if err := cw.Close(); err != nil {
			return err
		}
	}
	return o.Close()
}

func writeSingle(out string, files []*InputFile, codec string, opt AddOptions, prog *Progress) error {
	var src *InputFile
	for _, f := range files {
		if !f.IsDir {
			if src != nil {
				return fmt.Errorf("%s 只能压缩单个文件，多个文件请用 tar.%s 或 7z/zip", codec, codec)
			}
			src = f
		}
	}
	if src == nil {
		return fmt.Errorf("%s 需要一个普通文件作为输入", codec)
	}
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	cw, err := newCompressor(codec, o, opt.Level, opt.Threads)
	if err != nil {
		return err
	}
	if gz, ok := cw.(*gzip.Writer); ok {
		gz.Name = path.Base(src.Name)
		gz.ModTime = src.ModTime
	}
	if err := copyFile(cw, src, prog); err != nil {
		return err
	}
	if err := cw.Close(); err != nil {
		return err
	}
	return o.Close()
}
