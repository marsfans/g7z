package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/dsnet/compress/bzip2"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

// Format 描述一种压缩/归档格式
type Format struct {
	Name     string   // 规范名，如 7z / zip / tar.gz / gz
	Exts     []string // 识别用扩展名
	Write    bool
	Read     bool
	Archive  bool   // 多文件归档（否则为单文件压缩流）
	Codec    string // tar.* / 单文件流 使用的压缩算法
	Desc     string
	Password string // 加密支持说明
}

var formats = []Format{
	{Name: "7z", Exts: []string{".7z"}, Write: true, Read: true, Archive: true, Desc: "LZMA2 固实压缩，多线程分块", Password: "读写 AES-256"},
	{Name: "zip", Exts: []string{".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".epub", ".cbz"}, Write: true, Read: true, Archive: true, Desc: "Deflate（读取另支持 zstd/xz）", Password: "读写 AES-256，读 ZipCrypto"},
	{Name: "tar", Exts: []string{".tar"}, Write: true, Read: true, Archive: true, Desc: "不压缩打包，保留权限与符号链接"},
	{Name: "tar.gz", Exts: []string{".tar.gz", ".tgz"}, Write: true, Read: true, Archive: true, Codec: "gz", Desc: "tar + gzip"},
	{Name: "tar.bz2", Exts: []string{".tar.bz2", ".tbz2", ".tbz"}, Write: true, Read: true, Archive: true, Codec: "bz2", Desc: "tar + bzip2"},
	{Name: "tar.xz", Exts: []string{".tar.xz", ".txz"}, Write: true, Read: true, Archive: true, Codec: "xz", Desc: "tar + xz (LZMA2)"},
	{Name: "tar.zst", Exts: []string{".tar.zst", ".tzst", ".tar.zstd"}, Write: true, Read: true, Archive: true, Codec: "zst", Desc: "tar + zstd（多线程）"},
	{Name: "tar.lz4", Exts: []string{".tar.lz4", ".tlz4"}, Write: true, Read: true, Archive: true, Codec: "lz4", Desc: "tar + lz4（多线程）"},
	{Name: "tar.br", Exts: []string{".tar.br", ".tbr"}, Write: true, Read: true, Archive: true, Codec: "br", Desc: "tar + brotli"},
	{Name: "rar", Exts: []string{".rar"}, Read: true, Archive: true, Desc: "RAR4 / RAR5，含分卷（只读）", Password: "读"},
	{Name: "gz", Exts: []string{".gz", ".gzip"}, Write: true, Read: true, Codec: "gz", Desc: "单文件 gzip"},
	{Name: "bz2", Exts: []string{".bz2"}, Write: true, Read: true, Codec: "bz2", Desc: "单文件 bzip2"},
	{Name: "xz", Exts: []string{".xz"}, Write: true, Read: true, Codec: "xz", Desc: "单文件 xz"},
	{Name: "zst", Exts: []string{".zst", ".zstd"}, Write: true, Read: true, Codec: "zst", Desc: "单文件 zstd"},
	{Name: "lz4", Exts: []string{".lz4"}, Write: true, Read: true, Codec: "lz4", Desc: "单文件 lz4"},
	{Name: "br", Exts: []string{".br"}, Write: true, Read: true, Codec: "br", Desc: "单文件 brotli"},
}

func formatByName(name string) (*Format, error) {
	n := strings.ToLower(strings.TrimPrefix(name, "."))
	alias := map[string]string{"tgz": "tar.gz", "tbz2": "tar.bz2", "txz": "tar.xz", "tzst": "tar.zst", "gzip": "gz", "bzip2": "bz2", "zstd": "zst", "brotli": "br", "tar.zstd": "tar.zst"}
	if a, ok := alias[n]; ok {
		n = a
	}
	for i := range formats {
		if formats[i].Name == n {
			return &formats[i], nil
		}
	}
	return nil, fmt.Errorf("不支持的格式: %s（用 g7z i 查看支持列表）", name)
}

// formatByExt 按文件名推断格式，优先匹配最长扩展名
func formatByExt(path string) *Format {
	lower := strings.ToLower(filepath.Base(path))
	var best *Format
	bestLen := 0
	for i := range formats {
		for _, e := range formats[i].Exts {
			if strings.HasSuffix(lower, e) && len(e) > bestLen {
				best, bestLen = &formats[i], len(e)
			}
		}
	}
	return best
}

// sniffFormat 按文件头魔数识别，失败回退扩展名
func sniffFormat(path string) (*Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	byExt := formatByExt(path)
	codec := ""
	switch {
	case bytes.HasPrefix(head, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}):
		return formatByName("7z")
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")), bytes.HasPrefix(head, []byte("PK\x07\x08")):
		return formatByName("zip")
	case bytes.HasPrefix(head, []byte("Rar!\x1a\x07")):
		return formatByName("rar")
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		codec = "gz"
	case bytes.HasPrefix(head, []byte("BZh")):
		codec = "bz2"
	case bytes.HasPrefix(head, []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}):
		codec = "xz"
	case bytes.HasPrefix(head, []byte{0x28, 0xB5, 0x2F, 0xFD}):
		codec = "zst"
	case bytes.HasPrefix(head, []byte{0x04, 0x22, 0x4D, 0x18}):
		codec = "lz4"
	case n >= 262 && string(head[257:262]) == "ustar":
		return formatByName("tar")
	}
	if codec == "" {
		if byExt != nil && byExt.Read {
			if byExt.Codec == "br" || byExt.Name == "tar" {
				return byExt, nil
			}
		}
		// 自解压 7z（exe 前缀）等：扫描签名
		if byExt == nil || byExt.Name == "7z" {
			return formatByName("7z")
		}
		return nil, fmt.Errorf("无法识别的归档格式: %s", path)
	}
	// 压缩流：解压一段看看里面是不是 tar
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	rc, err := newDecompressor(codec, f)
	if err == nil {
		defer rc.Close()
		inner := make([]byte, 512)
		m, _ := io.ReadFull(rc, inner)
		if m >= 262 && string(inner[257:262]) == "ustar" {
			return formatByName("tar." + codec)
		}
	}
	if byExt != nil && byExt.Archive && byExt.Codec == codec {
		return byExt, nil
	}
	return formatByName(codec)
}

// ---------- 压缩/解压流 ----------

type nopCloser struct{ io.Reader }

func (nopCloser) Close() error { return nil }

type funcCloser struct {
	io.Reader
	close func() error
}

func (f funcCloser) Close() error { return f.close() }

func newDecompressor(codec string, r io.Reader) (io.ReadCloser, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	switch codec {
	case "gz":
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return zr, nil
	case "bz2":
		zr, err := bzip2.NewReader(br, nil)
		if err != nil {
			return nil, err
		}
		return zr, nil
	case "xz":
		zr, err := xz.NewReader(br)
		if err != nil {
			return nil, err
		}
		return nopCloser{zr}, nil
	case "zst":
		zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(0))
		if err != nil {
			return nil, err
		}
		return funcCloser{zr, func() error { zr.Close(); return nil }}, nil
	case "lz4":
		return nopCloser{lz4.NewReader(br)}, nil
	case "br":
		return nopCloser{brotli.NewReader(br)}, nil
	case "":
		return nopCloser{br}, nil
	}
	return nil, fmt.Errorf("未知压缩算法 %s", codec)
}

// newCompressor level 取 0-9（7z 的 -mx 语义），threads 为线程数
func newCompressor(codec string, w io.Writer, level, threads int) (io.WriteCloser, error) {
	if level < 1 {
		level = 1
	}
	if level > 9 {
		level = 9
	}
	switch codec {
	case "gz":
		return gzip.NewWriterLevel(w, level)
	case "bz2":
		return bzip2.NewWriter(w, &bzip2.WriterConfig{Level: level})
	case "xz":
		cfg := xz.WriterConfig{DictCap: dictForLevel(level)}
		return cfg.NewWriter(w)
	case "zst":
		lv := zstd.SpeedDefault
		switch {
		case level <= 2:
			lv = zstd.SpeedFastest
		case level <= 5:
			lv = zstd.SpeedDefault
		case level <= 7:
			lv = zstd.SpeedBetterCompression
		default:
			lv = zstd.SpeedBestCompression
		}
		return zstd.NewWriter(w, zstd.WithEncoderLevel(lv), zstd.WithEncoderConcurrency(threads))
	case "lz4":
		zw := lz4.NewWriter(w)
		lv := lz4.Fast
		if level >= 3 {
			lv = lz4.CompressionLevel(1 << (8 + level))
		}
		if err := zw.Apply(lz4.CompressionLevelOption(lv), lz4.ConcurrencyOption(threads)); err != nil {
			return nil, err
		}
		return zw, nil
	case "br":
		return brotli.NewWriterLevel(w, level+2), nil
	}
	return nil, fmt.Errorf("未知压缩算法 %s", codec)
}

// dictForLevel 与 7-Zip 的 -mx 级别大致对应的 LZMA2 字典大小
func dictForLevel(level int) int {
	switch {
	case level <= 1:
		return 1 << 20
	case level <= 3:
		return 4 << 20
	case level <= 5:
		return 16 << 20
	case level <= 7:
		return 32 << 20
	default:
		return 64 << 20
	}
}
