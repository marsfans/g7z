package main

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bodgit/sevenzip"
	"github.com/nwaples/rardecode/v2"
	"github.com/pterm/pterm"
	yzip "github.com/yeka/zip"
)

type ExtractOptions struct {
	OutDir    string
	Flat      bool   // e 命令：不保留目录
	Overwrite string // ask / a(全部覆盖) / s(跳过) / u(自动重命名)
	Filters   []string
	Test      bool
	Password  string
}

type ExtractStats struct {
	Files, Dirs, Skipped, Errors int
	Bytes                        int64
}

func isPwError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errNeedPassword) || errors.Is(err, rardecode.ErrArchiveEncrypted) || errors.Is(err, rardecode.ErrArchivedFileEncrypted) {
		return true
	}
	var re sevenzip.ReadError
	if errors.As(err, &re) && re.Encrypted {
		return true
	}
	return false
}

// needsPassword 在没有密码时探测归档是否加密
func needsPassword(p string, fm *Format) bool {
	switch fm.Name {
	case "zip":
		r, err := yzip.OpenReader(p)
		if err != nil {
			return false
		}
		defer r.Close()
		for _, f := range r.File {
			if f.IsEncrypted() {
				return true
			}
		}
	case "7z":
		r, err := sevenzip.OpenReader(p)
		if err != nil {
			var re sevenzip.ReadError
			return isPwError(err) || errors.As(err, &re) || strings.Contains(strings.ToLower(err.Error()), "password") || strings.Contains(err.Error(), "read error")
		}
		defer r.Close()
		for _, f := range r.File {
			if f.UncompressedSize > 0 {
				rc, err := f.Open()
				if err != nil {
					return isPwError(err)
				}
				_, err = rc.Read(make([]byte, 1))
				rc.Close()
				return err != nil && err != io.EOF
			}
		}
	case "rar":
		r, err := rardecode.OpenReader(p)
		if err != nil {
			return isPwError(err)
		}
		defer r.Close()
		for {
			h, err := r.Next()
			if err != nil {
				return isPwError(err)
			}
			if h.Encrypted {
				return true
			}
		}
	}
	return false
}

func matchFilter(name string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	n := strings.TrimSuffix(name, "/")
	for _, f := range filters {
		f = strings.TrimSuffix(filepath.ToSlash(f), "/")
		if ok, _ := path.Match(f, n); ok {
			return true
		}
		if ok, _ := path.Match(f, path.Base(n)); ok {
			return true
		}
		if strings.HasPrefix(n, f+"/") {
			return true
		}
	}
	return false
}

// safeName 去掉绝对路径、盘符和 ..，防止目录穿越
func safeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if len(name) >= 2 && name[1] == ':' {
		name = name[2:]
	}
	var parts []string
	for _, p := range strings.Split(name, "/") {
		switch p {
		case "", ".":
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			if runtime.GOOS == "windows" {
				p = strings.Map(func(r rune) rune {
					if strings.ContainsRune(`<>:"|?*`, r) || r < 32 {
						return '_'
					}
					return r
				}, p)
				p = strings.TrimRight(p, ". ")
			}
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "/")
}

func uniqueName(p string) string {
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	for i := 1; ; i++ {
		c := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Lstat(c); os.IsNotExist(err) {
			return c
		}
	}
}

// resolveOverwrite 返回最终路径，"" 表示跳过
func resolveOverwrite(target string, opt *ExtractOptions) (string, error) {
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		return target, nil
	}
	mode := opt.Overwrite
	if mode == "ask" {
		if !stdinTTY {
			mode = "s"
		} else {
			clearLine()
			choices := []string{"覆盖", "跳过", "全部覆盖", "全部跳过", "自动重命名", "全部自动重命名"}
			sel, err := pterm.DefaultInteractiveSelect.WithOptions(choices).WithDefaultText("文件已存在: " + target).Show()
			if err != nil {
				return "", err
			}
			switch sel {
			case "覆盖":
				mode = "a"
			case "跳过":
				mode = "s"
			case "全部覆盖":
				opt.Overwrite, mode = "a", "a"
			case "全部跳过":
				opt.Overwrite, mode = "s", "s"
			case "自动重命名":
				mode = "u"
			case "全部自动重命名":
				opt.Overwrite, mode = "u", "u"
			}
		}
	}
	switch mode {
	case "a":
		if st, err := os.Lstat(target); err == nil && !st.IsDir() {
			os.Remove(target)
		}
		return target, nil
	case "u":
		return uniqueName(target), nil
	}
	return "", nil
}

type crcCheck struct {
	r   io.Reader
	h   uint32
	tab *crc32.Table
}

func (c *crcCheck) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.h = crc32.Update(c.h, crc32.IEEETable, p[:n])
	return n, err
}

func runExtract(archive string, fm *Format, opt *ExtractOptions, prog *Progress) (*ExtractStats, error) {
	st := &ExtractStats{}
	type dirTime struct {
		p string
		t time.Time
	}
	var dirTimes []dirTime
	buf := make([]byte, 1<<20)
	err := walkArchive(archive, fm, opt.Password, func(e *Entry, open func() (io.ReadCloser, error)) error {
		if !matchFilter(e.Name, opt.Filters) {
			return nil
		}
		name := safeName(e.Name)
		if name == "" {
			return nil
		}
		prog.SetCurrent(name)
		if opt.Test {
			if e.IsDir || e.Link != "" {
				return nil
			}
			rc, err := open()
			if err != nil {
				return err
			}
			cc := &crcCheck{r: rc}
			n, err := io.CopyBuffer(prog, cc, buf)
			rc.Close()
			_ = n
			if err != nil {
				if isPwError(err) {
					return err
				}
				st.Errors++
				logErr("%s: %v", name, wrapPwErr(err, opt.Password))
				return nil
			}
			if e.HasCRC && e.CRC != cc.h && fm.Name == "7z" {
				st.Errors++
				logErr("%s: CRC 校验失败", name)
				return nil
			}
			st.Files++
			st.Bytes += n
			return nil
		}
		if opt.Flat {
			if e.IsDir {
				return nil
			}
			name = path.Base(name)
		}
		target := filepath.Join(opt.OutDir, filepath.FromSlash(name))
		if e.IsDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			dirTimes = append(dirTimes, dirTime{target, e.ModTime})
			st.Dirs++
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		final, err := resolveOverwrite(target, opt)
		if err != nil {
			return err
		}
		if final == "" {
			st.Skipped++
			return nil
		}
		if e.Link != "" {
			if e.HardLink {
				src := filepath.Join(opt.OutDir, filepath.FromSlash(safeName(e.Link)))
				if err := os.Link(src, final); err != nil {
					if err := copyPath(src, final); err != nil {
						logWarn("硬链接 %s 失败: %v", name, err)
					}
				}
			} else if err := os.Symlink(e.Link, final); err != nil {
				logWarn("符号链接 %s -> %s 创建失败: %v", name, e.Link, err)
			}
			st.Files++
			return nil
		}
		rc, err := open()
		if err != nil {
			return err
		}
		perm := e.Mode.Perm()
		if perm == 0 || runtime.GOOS == "windows" {
			perm = 0o644
		}
		out, err := os.OpenFile(final, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm|0o200)
		if err != nil {
			rc.Close()
			return err
		}
		n, err := io.CopyBuffer(io.MultiWriter(out, prog), rc, buf)
		rc.Close()
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(final)
			if isPwError(err) {
				return err
			}
			st.Errors++
			logErr("%s: %v", name, wrapPwErr(err, opt.Password))
			return nil
		}
		if perm&0o200 == 0 {
			os.Chmod(final, perm)
		}
		if !e.ModTime.IsZero() {
			os.Chtimes(final, e.ModTime, e.ModTime)
		}
		st.Files++
		st.Bytes += n
		return nil
	})
	for i := len(dirTimes) - 1; i >= 0; i-- {
		if !dirTimes[i].t.IsZero() {
			os.Chtimes(dirTimes[i].p, dirTimes[i].t, dirTimes[i].t)
		}
	}
	return st, err
}

func copyPath(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// archiveTotal 对 7z/zip 预先统计解压总大小（只读目录，不解压）
func archiveTotal(p string, fm *Format, password string, filters []string) int64 {
	var total int64
	switch fm.Name {
	case "7z", "zip":
		_ = walkArchive(p, fm, password, func(e *Entry, _ func() (io.ReadCloser, error)) error {
			if !e.IsDir && e.Size > 0 && matchFilter(e.Name, filters) {
				total += e.Size
			}
			return nil
		})
		return total
	}
	return -1
}
