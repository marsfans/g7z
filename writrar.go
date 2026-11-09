package main

import (
	"fmt"
	"os"

	"github.com/marsfans/g7z/rarpack"
)

// writeRar 写 RAR5 归档（rarpack 实现）：固实、E8E9 过滤、AES-256 加密与头部加密。
// RAR 不单独存储目录项，目录结构由文件路径保留；空目录不会写入。
func writeRar(out string, files []*InputFile, opt AddOptions, prog *Progress) error {
	entries := make([]rarpack.Entry, 0, len(files))
	for _, f := range files {
		if f.IsDir {
			continue
		}
		if f.Link != "" {
			logWarn("rar 不保留符号链接，已跳过 %s", f.Name)
			continue
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return err
		}
		entries = append(entries, rarpack.Entry{Name: f.Name, Data: data, ModTime: f.ModTime})
	}
	if len(entries) == 0 {
		return fmt.Errorf("没有可压缩的普通文件")
	}
	ro := rarpack.DefaultOptions()
	ro.Solid = opt.Solid != 1 // -ms=off 解析为 1；其余（默认 64m/on）为固实
	ro.Password = opt.Password
	ro.HeaderEncryption = opt.MHE && opt.Password != ""
	ro.Report = func(s rarpack.FileStat) {
		prog.SetCurrent(s.Name)
		prog.Add(s.Size)
	}
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	if err := rarpack.Archive(o, ro, entries); err != nil {
		o.Close()
		return err
	}
	return o.Close()
}
