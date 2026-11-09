package cpio

import (
	"io"
)

// Writer writes a newc (070701) cpio stream.
type Writer struct {
	w      io.Writer
	total  int64 // bytes written so far
	left   int64 // data bytes still owed for the current entry
	pad    int64 // data padding to flush before the next header
	closed bool
	err    error
}

// NewWriter returns a Writer writing to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (w *Writer) write(p []byte) error {
	if w.err != nil {
		return w.err
	}
	n, err := w.w.Write(p)
	w.total += int64(n)
	if err != nil {
		w.err = err
		return err
	}
	if n != len(p) {
		w.err = io.ErrShortWrite
		return w.err
	}
	return nil
}

// WriteHeader writes the header for the next entry. The caller must
// then write exactly Header.Size bytes of data (zero for directories,
// links and other data-less entries).
func (w *Writer) WriteHeader(h *Header) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return io.ErrClosedPipe
	}
	if w.left > 0 {
		return ErrIncompleteEntry
	}
	if w.pad > 0 {
		if err := w.write(make([]byte, w.pad)); err != nil {
			return err
		}
		w.pad = 0
	}
	name := h.Name
	nameSize := int64(len(name)) + 1
	fields := [13]uint32{
		h.Ino, h.Mode, h.Uid, h.Gid, h.Nlink,
		uint32(h.ModTime.Unix()), uint32(h.Size),
		h.DevMajor, h.DevMinor, h.RDevMajor, h.RDevMinor,
		uint32(nameSize), 0,
	}
	if h.Nlink == 0 {
		fields[4] = 1
	}
	var hdr [headerSize]byte
	copy(hdr[:], "070701")
	for i, v := range fields {
		putHex(hdr[6+i*8:], v)
	}
	if err := w.write(hdr[:]); err != nil {
		return err
	}
	if err := w.write([]byte(name)); err != nil {
		return err
	}
	if err := w.write(make([]byte, 1+pad4(headerSize+nameSize))); err != nil {
		return err
	}
	w.left = h.Size
	w.pad = pad4(h.Size)
	return nil
}

// Write writes data for the current entry.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > w.left {
		return 0, ErrWriteTooLong
	}
	if err := w.write(p); err != nil {
		return 0, err
	}
	w.left -= int64(len(p))
	return len(p), nil
}

// Close writes the trailer entry and pads the archive to a 512-byte
// boundary, as GNU cpio does.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	if w.left > 0 {
		return ErrIncompleteEntry
	}
	if w.pad > 0 {
		if err := w.write(make([]byte, w.pad)); err != nil {
			return err
		}
		w.pad = 0
	}
	if err := w.WriteHeader(&Header{Name: "TRAILER!!!", Nlink: 1}); err != nil {
		return err
	}
	w.closed = true
	// The trailer itself declares size 0, so only alignment remains.
	if rem := w.total % 512; rem != 0 {
		if err := w.write(make([]byte, 512-rem)); err != nil {
			return err
		}
	}
	return w.err
}

func putHex(dst []byte, v uint32) {
	const digits = "0123456789abcdef"
	for i := 7; i >= 0; i-- {
		dst[i] = digits[v&0xf]
		v >>= 4
	}
}
