// Package cpio reads and writes cpio archives in the "newc" format
// (SVR4, magic 070701) and reads the "crc" variant (magic 070702,
// per-file byte checksum). This is the format used by Linux initramfs
// images and RPM packages.
//
// Each entry is a 110-byte ASCII header of hexadecimal fields,
// followed by the NUL-terminated name, NUL padding to a 4-byte
// boundary, the file data, and NUL padding to a 4-byte boundary. A
// trailer entry named TRAILER!!! ends the archive.
package cpio

import (
	"errors"
	"io/fs"
	"time"
)

// Unix mode type bits, as stored in the header's mode field.
const (
	sIFMT   = 0o170000
	sIFREG  = 0o100000
	sIFDIR  = 0o040000
	sIFLNK  = 0o120000
	sIFCHR  = 0o020000
	sIFBLK  = 0o060000
	sIFIFO  = 0o010000
	sIFSOCK = 0o140000
)

var (
	// ErrMalformed reports a structurally invalid archive.
	ErrMalformed = errors.New("cpio: malformed archive")
	// ErrChecksum reports a crc-variant entry whose data does not
	// match its stored checksum.
	ErrChecksum = errors.New("cpio: checksum mismatch")
	// ErrTruncated reports an archive that ends mid-entry.
	ErrTruncated = errors.New("cpio: truncated archive")
	// ErrWriteTooLong reports a Write larger than the size declared
	// in the entry header.
	ErrWriteTooLong = errors.New("cpio: write exceeds declared size")
	// ErrIncompleteEntry reports a new header or Close while the
	// previous entry's data is not fully written.
	ErrIncompleteEntry = errors.New("cpio: previous entry data incomplete")
)

// Header is one cpio entry's metadata. Mode is the raw Unix mode
// (file type bits, permission bits, setuid/setgid/sticky).
type Header struct {
	Name      string
	Ino       uint32
	Mode      uint32
	Uid       uint32
	Gid       uint32
	Nlink     uint32
	ModTime   time.Time
	Size      int64
	DevMajor  uint32
	DevMinor  uint32
	RDevMajor uint32
	RDevMinor uint32
	Check     uint32 // crc variant: sum of all data bytes
}

// Type returns the file-type bits of the entry (Mode & 0o170000).
func (h *Header) Type() uint32 { return h.Mode & sIFMT }

// IsDir reports whether the entry is a directory.
func (h *Header) IsDir() bool { return h.Type() == sIFDIR }

// IsSymlink reports whether the entry is a symbolic link. Its data is
// the link target.
func (h *Header) IsSymlink() bool { return h.Type() == sIFLNK }

// IsRegular reports whether the entry is a regular file.
func (h *Header) IsRegular() bool { return h.Type() == sIFREG || h.Type() == 0 }

// FileMode converts the raw Unix mode to an fs.FileMode.
func (h *Header) FileMode() fs.FileMode {
	fm := fs.FileMode(h.Mode & 0o777)
	switch h.Type() {
	case sIFDIR:
		fm |= fs.ModeDir
	case sIFLNK:
		fm |= fs.ModeSymlink
	case sIFBLK:
		fm |= fs.ModeDevice
	case sIFCHR:
		fm |= fs.ModeDevice | fs.ModeCharDevice
	case sIFIFO:
		fm |= fs.ModeNamedPipe
	case sIFSOCK:
		fm |= fs.ModeSocket
	}
	if h.Mode&0o4000 != 0 {
		fm |= fs.ModeSetuid
	}
	if h.Mode&0o2000 != 0 {
		fm |= fs.ModeSetgid
	}
	if h.Mode&0o1000 != 0 {
		fm |= fs.ModeSticky
	}
	return fm
}

// UnixMode converts an fs.FileMode back to a raw Unix mode, for
// building headers from file information.
func UnixMode(fm fs.FileMode) uint32 {
	m := uint32(fm.Perm())
	switch {
	case fm.IsDir():
		m |= sIFDIR
	case fm&fs.ModeSymlink != 0:
		m |= sIFLNK
	case fm&fs.ModeCharDevice != 0:
		m |= sIFCHR
	case fm&fs.ModeDevice != 0:
		m |= sIFBLK
	case fm&fs.ModeNamedPipe != 0:
		m |= sIFIFO
	case fm&fs.ModeSocket != 0:
		m |= sIFSOCK
	default:
		m |= sIFREG
	}
	if fm&fs.ModeSetuid != 0 {
		m |= 0o4000
	}
	if fm&fs.ModeSetgid != 0 {
		m |= 0o2000
	}
	if fm&fs.ModeSticky != 0 {
		m |= 0o1000
	}
	return m
}
