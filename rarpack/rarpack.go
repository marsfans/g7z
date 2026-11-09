// Package rarpack is a pure-Go RAR5 (algorithm version 0) compressor.
//
// It writes archives that standard tools (WinRAR, the official unrar,
// Go rardecode) can extract: LZ matching with a 16 MB dictionary,
// per-block canonical Huffman coding, optional solid mode, repeat
// distances, and the E8/E8E9 filter for PE files. Compression strategy
// is an original simplified implementation (greedy + lazy matching);
// it does not reproduce RAR's proprietary encoder heuristics, so ratios
// are a few percent behind WinRAR -m5 on typical data.
//
// Encryption is supported via Options.Password (AES-256-CBC,
// PBKDF2-HMAC-SHA256), including header encryption
// (Options.HeaderEncryption, WinRAR "-hp" mode).
//
// A Writer buffers all entries and produces the archive on Close,
// because solid compression needs the whole file set up front. Memory
// use is therefore proportional to the total input size.
package rarpack

import (
	"errors"
	"io"
	"os"
	"time"
)

// Options controls archive creation.
type Options struct {
	// Solid shares one compression dictionary across all files (in Add
	// order). Big win when files resemble each other; requires
	// sequential extraction from the start of the archive.
	Solid bool

	// Filters enables the E8/E8E9 filter for PE (MZ) files up to 4 MB.
	// In non-solid mode both variants are tried and the smaller kept;
	// in solid mode the filter is applied heuristically.
	Filters bool

	// Password, if non-empty, encrypts every file's data with
	// AES-256-CBC (RAR5 "-p" mode): per-file random salt and IV,
	// PBKDF2-HMAC-SHA256 key derivation (2^15 iterations), a password
	// check value so wrong passwords are rejected immediately, and a
	// MAC-protected stored CRC32. File names and sizes stay readable;
	// header encryption ("-hp") is not supported. The password is
	// UTF-8 encoded for key derivation, as in WinRAR.
	Password string

	// HeaderEncryption additionally encrypts every archive header
	// (WinRAR "-hp" mode): file names and sizes are hidden until the
	// password is given. Requires Password. All headers and file data
	// then share one archive-wide salt and key set (per-header and
	// per-file IVs), and stored CRC32s are plain, mirroring WinRAR.
	HeaderEncryption bool

	// Report, if set, is called for each file during Close with its
	// packed result. Optional.
	Report func(FileStat)
}

// DefaultOptions returns the recommended settings: solid + filters.
func DefaultOptions() *Options {
	return &Options{Solid: true, Filters: true}
}

// FileStat reports the packed outcome for one file.
type FileStat struct {
	Name       string
	Size       int64 // unpacked size
	PackedSize int64 // size of its data area in the archive
	Stored     bool  // true if stored uncompressed
	Filtered   bool  // true if the E8/E8E9 filter was applied
	Encrypted  bool  // true if the data area is encrypted
}

// Entry is one file to place into an archive.
type Entry struct {
	Name    string // name inside the archive (UTF-8, '/' separators)
	Data    []byte
	ModTime time.Time // zero means "now" at build time
}

// Writer accumulates entries and writes a RAR5 archive on Close.
type Writer struct {
	w       io.Writer
	opts    *Options
	entries []Entry
	closed  bool
}

// NewWriter creates a Writer. A nil opts uses DefaultOptions.
func NewWriter(w io.Writer, opts *Options) *Writer {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Writer{w: w, opts: opts}
}

// Add appends one file to the archive. Data is not copied; the caller
// must not modify it before Close.
func (w *Writer) Add(name string, data []byte, modTime time.Time) error {
	if w.closed {
		return errors.New("rarpack: Add after Close")
	}
	if name == "" {
		return errors.New("rarpack: empty file name")
	}
	w.entries = append(w.entries, Entry{Name: name, Data: data, ModTime: modTime})
	return nil
}

// AddReader is Add with data read fully from r.
func (w *Writer) AddReader(name string, r io.Reader, modTime time.Time) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return w.Add(name, data, modTime)
}

// AddFile adds a file from disk, using its base name and mtime.
func (w *Writer) AddFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return w.Add(pathBase(path), data, info.ModTime())
}

// Close builds and writes the archive. It does not close the
// underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return errors.New("rarpack: Close called twice")
	}
	w.closed = true
	arc, err := buildArchive(w.entries, w.opts)
	if err != nil {
		return err
	}
	_, err = w.w.Write(arc)
	return err
}

// Archive writes a complete archive for entries to w in one call.
func Archive(w io.Writer, opts *Options, entries []Entry) error {
	wr := NewWriter(w, opts)
	for _, e := range entries {
		if err := wr.Add(e.Name, e.Data, e.ModTime); err != nil {
			return err
		}
	}
	return wr.Close()
}

// WriteFile creates the archive file at path in one call.
func WriteFile(path string, opts *Options, entries []Entry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := Archive(f, opts, entries); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func pathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
