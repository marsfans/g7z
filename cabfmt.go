package main

import (
	"io"
	"os"
	"strings"

	cabinet "github.com/abemedia/go-cabinet"
)

// walkCab streams a Microsoft Cabinet archive (via go-cabinet:
// stored / MSZIP / LZX, single-cabinet only).
func walkCab(path string, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rd, err := cabinet.NewReader(f)
	if err != nil {
		return err
	}
	for _, cf := range rd.Files {
		e := &Entry{
			Name:    strings.ReplaceAll(cf.Name, "\\", "/"),
			Size:    int64(cf.Size()),
			Packed:  -1,
			ModTime: cf.Modified,
			Mode:    0644,
		}
		if err := fn(e, func() (io.ReadCloser, error) { return cf.Open() }); err != nil {
			return err
		}
	}
	return nil
}

// writeCab writes all files into a single-folder cabinet.
// Level 0 stores, 1-6 use MSZIP, 7-9 use LZX (window 21).
func writeCab(out string, files []*InputFile, opt AddOptions, prog *Progress) error {
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	w := cabinet.NewWriter(o)
	comp := cabinet.MSZIP
	switch {
	case opt.Level == 0:
		comp = cabinet.None
	case opt.Level >= 7:
		comp = cabinet.LZX
	}
	if err := w.SetCompression(comp); err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir {
			continue // CAB has no directory entries; paths live in file names
		}
		fh := &cabinet.FileHeader{
			Name:     strings.ReplaceAll(f.Name, "/", "\\"),
			Modified: f.ModTime,
		}
		cw, err := w.CreateHeader(fh)
		if err != nil {
			return err
		}
		if err := copyFile(cw, f, prog); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	return o.Close()
}
