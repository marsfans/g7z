package main

import (
	"bytes"
	"io"
	"os"

	wimpkg "github.com/marsfans/g7z/wim"
)

// walkWim streams image 1 of a WIM file (stored / XPRESS / LZX
// resources; LZMS and solid images are rejected by the reader).
func walkWim(path string, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	rd, err := wimpkg.OpenReader(f, st.Size())
	if err != nil {
		return err
	}
	entries, err := rd.Image(1)
	if err != nil {
		return err
	}
	for _, e := range entries {
		ge := &Entry{
			Name:    e.Name,
			Size:    e.Size,
			Packed:  -1,
			ModTime: e.ModTime,
			Mode:    e.Mode,
			IsDir:   e.IsDir,
		}
		if e.HardlinkTo != "" {
			ge.Link = e.HardlinkTo
			ge.HardLink = true
		}
		ee := e
		if err := fn(ge, func() (io.ReadCloser, error) { return rd.Open(ee) }); err != nil {
			return err
		}
	}
	return nil
}

// writeWim builds a single-image WIM. Level 0 stores resources,
// levels above 0 compress with XPRESS. File contents are buffered
// in memory (WIM needs each file's SHA-1 before its metadata can
// be written).
func writeWim(out string, files []*InputFile, opt AddOptions, prog *Progress) error {
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	w := wimpkg.NewWriter(o, opt.Level)
	for _, f := range files {
		var content []byte
		if !f.IsDir {
			var buf bytes.Buffer
			if err := copyFile(&buf, f, prog); err != nil {
				return err
			}
			content = buf.Bytes()
		}
		if err := w.Add(f.Name, fileInfoOf(f).Mode(), f.ModTime, f.IsDir, content); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	return o.Close()
}
