package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marsfans/g7z/iso"
)

// walkISO streams an ISO 9660 image with the in-tree reader
// (g7z/iso; Rock Ridge names and POSIX modes are honoured when
// present).
func walkISO(path string, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	img, err := iso.Open(f)
	if err != nil {
		return err
	}
	return walkISOChildren(img.Root(), "", fn)
}

func walkISOChildren(dir *iso.File, prefix string, fn WalkFunc) error {
	children, err := dir.Children()
	if err != nil {
		return err
	}
	for _, c := range children {
		name := prefix + c.Name
		e := &Entry{
			Name:    name,
			Packed:  -1,
			ModTime: c.ModTime,
			Mode:    c.Mode,
			IsDir:   c.IsDir,
		}
		if !c.IsDir {
			e.Size = c.Size
		}
		cf := c
		if err := fn(e, func() (io.ReadCloser, error) {
			return io.NopCloser(cf.Open()), nil
		}); err != nil {
			return err
		}
		if c.IsDir {
			if err := walkISOChildren(c, name+"/", fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeISO builds an ISO 9660 image with the in-tree writer
// (g7z/iso): Rock Ridge entries preserve long names, POSIX modes
// and timestamps; plain ISO readers see mangled names.
func writeISO(out string, files []*InputFile, opt AddOptions, prog *Progress) error {
	entries := make([]*iso.Entry, 0, len(files))
	for _, f := range files {
		e := &iso.Entry{
			Name:    f.Name,
			Size:    f.Size,
			ModTime: f.ModTime,
			Mode:    f.Mode,
			IsDir:   f.IsDir,
		}
		if !f.IsDir {
			p := f.Path
			e.Open = func() (io.ReadCloser, error) {
				src, err := os.Open(p)
				if err != nil {
					return nil, err
				}
				return &progReadCloser{Reader: io.TeeReader(src, prog), c: src}, nil
			}
		}
		entries = append(entries, e)
	}
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	if err := iso.Create(o, isoVolumeLabel(out), entries); err != nil {
		return err
	}
	return o.Close()
}

// progReadCloser reports read progress while streaming a file
// into an archive and closes the underlying file.
type progReadCloser struct {
	io.Reader
	c io.Closer
}

func (p *progReadCloser) Close() error { return p.c.Close() }

// isoVolumeLabel derives a valid ISO 9660 volume identifier
// (uppercase d-characters, max 32) from the output file name.
func isoVolumeLabel(out string) string {
	base := filepath.Base(out)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	var b strings.Builder
	for _, r := range strings.ToUpper(base) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 32 {
		s = s[:32]
	}
	if s == "" {
		s = "G7Z"
	}
	return s
}
