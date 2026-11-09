package rarpack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"time"
)

// ---------- RAR5 archive assembly (headers + per-file streams) ----------

var rarSignature = []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}

func vint(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			return out
		}
	}
}

// header wraps a block body with its size and CRC32 (CRC covers the
// HeadSize field through the end of the header, per RAR5 spec; verified
// against the official installer archive).
func header(body []byte) []byte {
	var full bytes.Buffer
	full.Write(vint(uint64(len(body))))
	full.Write(body)
	crc := crc32.ChecksumIEEE(full.Bytes())
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, crc)
	return append(out, full.Bytes()...)
}

func mainHeader(solid bool) []byte {
	var body bytes.Buffer
	body.Write(vint(1)) // HEAD_MAIN
	body.Write(vint(0)) // header flags
	archFlags := uint64(0)
	if solid {
		archFlags = 0x04 // MHFL_SOLID
	}
	body.Write(vint(archFlags))
	return header(body.Bytes())
}

func endHeader() []byte {
	var body bytes.Buffer
	body.Write(vint(5))    // HEAD_ENDARC
	body.Write(vint(0x04)) // HFL_SKIPIFUNKNOWN, as written by WinRAR
	body.Write(vint(0))    // end flags
	return header(body.Bytes())
}

// fileHeader builds one HEAD_FILE. crcVal is the value stored in the
// header (MAC-protected in "-p" encryption mode). extra, when non-nil,
// is the extra area (e.g. an encryption record) appended after the
// file name.
func fileHeader(e Entry, pack []byte, method int, solidBit bool, crcVal uint32, extra []byte) []byte {
	var body bytes.Buffer
	body.Write(vint(2))       // HEAD_FILE
	headFlags := uint64(0x02) // HFL_DATA
	if extra != nil {
		headFlags |= 0x01 // HFL_EXTRA
	}
	body.Write(vint(headFlags))
	if extra != nil {
		body.Write(vint(uint64(len(extra))))
	}
	body.Write(vint(uint64(len(pack))))
	fileFlags := uint64(0x02 | 0x04) // FHFL_UTIME | FHFL_CRC32
	body.Write(vint(fileFlags))
	body.Write(vint(uint64(len(e.Data))))
	body.Write(vint(0x20)) // attributes: archive bit (Windows host)
	mt := e.ModTime
	if mt.IsZero() {
		mt = time.Now()
	}
	var tb [4]byte
	binary.LittleEndian.PutUint32(tb[:], uint32(mt.Unix()))
	body.Write(tb[:])
	binary.LittleEndian.PutUint32(tb[:], crcVal)
	body.Write(tb[:])
	comp := uint64(0) // algorithm version 0
	if method != 0 {
		comp = uint64(method)<<7 | uint64(dictFieldN)<<10
		if solidBit {
			comp |= 0x40 // FCI_SOLID
		}
	}
	body.Write(vint(comp))
	body.Write(vint(0)) // host OS: Windows
	name := []byte(e.Name)
	body.Write(vint(uint64(len(name))))
	body.Write(name)
	body.Write(extra)
	return header(body.Bytes())
}

// sealer applies the archive's encryption policy to file data areas.
type sealer struct {
	password string
	ac       *archiveCrypt // non-nil in header-encryption mode
}

func newSealer(opts *Options) (*sealer, error) {
	if opts.HeaderEncryption && opts.Password == "" {
		return nil, errors.New("rarpack: HeaderEncryption requires a Password")
	}
	s := &sealer{password: opts.Password}
	if opts.HeaderEncryption {
		ac, err := newArchiveCrypt(opts.Password)
		if err != nil {
			return nil, err
		}
		s.ac = ac
	}
	return s, nil
}

// seal encrypts one file's packed data if a password is set, and
// returns the data area, the header CRC value and the extra area.
// Unencrypted files (and empty data areas) pass through unchanged.
func (s *sealer) seal(e Entry, pack []byte) ([]byte, uint32, []byte, error) {
	crcVal := crc32.ChecksumIEEE(e.Data)
	if s.password == "" || len(pack) == 0 {
		return pack, crcVal, nil, nil
	}
	if s.ac != nil {
		// Header-encryption mode: archive-wide salt/key, per-file IV,
		// plain stored CRC (mirrors WinRAR -hp output).
		fc, err := s.ac.fileCrypt()
		if err != nil {
			return nil, 0, nil, err
		}
		return fc.encrypt(pack), crcVal, fc.extraRecord(), nil
	}
	fc, err := newFileCrypt(s.password)
	if err != nil {
		return nil, 0, nil, err
	}
	return fc.encrypt(pack), macCRC32(crcVal, fc.hashKey), fc.extraRecord(), nil
}

// segment is one piece of the archive body; headers are individually
// encrypted in header-encryption mode, data areas are not (they carry
// their own per-file encryption).
type segment struct {
	data     []byte
	isHeader bool
}

// buildArchive assembles a complete RAR5 archive from entries in order.
func buildArchive(entries []Entry, opts *Options) ([]byte, error) {
	s, err := newSealer(opts)
	if err != nil {
		return nil, err
	}
	var segs []segment
	addHeader := func(h []byte) { segs = append(segs, segment{h, true}) }
	addData := func(d []byte) { segs = append(segs, segment{d, false}) }
	report := func(e Entry, packed int, method int, filtered bool) {
		if opts.Report != nil {
			opts.Report(FileStat{Name: e.Name, Size: int64(len(e.Data)), PackedSize: int64(packed), Stored: method == 0, Filtered: filtered, Encrypted: opts.Password != "" && packed > 0})
		}
	}
	addHeader(mainHeader(opts.Solid))
	if opts.Solid {
		// The matcher runs over the concatenation of the (possibly
		// E8E9-transformed) file bytes, exactly like the decoder's
		// window holds transformed bytes per file region.
		tdata := make([][]byte, len(entries))
		useFilter := make([]bool, len(entries))
		var concat []byte
		offsets := make([]int, len(entries))
		for i, e := range entries {
			tdata[i] = e.Data
			if opts.Filters && isPE(e.Data) && len(e.Data) > 0 {
				tdata[i] = transformE8E9Chunked(e.Data)
				useFilter[i] = true
			}
			offsets[i] = len(concat)
			concat = append(concat, tdata[i]...)
		}
		m := newMatcher(concat)
		st := &streamState{}
		streamStarted := false
		for i, e := range entries {
			var pack []byte
			method := 0
			if len(e.Data) > 0 {
				pack = compressRange(m, st, offsets[i], offsets[i]+len(e.Data), useFilter[i])
				method = 3
			}
			pack, crcVal, extra, err := s.seal(e, pack)
			if err != nil {
				return nil, err
			}
			addHeader(fileHeader(e, pack, method, streamStarted && method != 0, crcVal, extra))
			if method != 0 {
				streamStarted = true
			}
			addData(pack)
			report(e, len(pack), method, useFilter[i])
		}
	} else {
		for _, e := range entries {
			pack := compressData(e.Data)
			method := 3
			filtered := false
			if pack == nil {
				pack = e.Data
				method = 0
			}
			if opts.Filters && isPE(e.Data) && len(e.Data) > 0 {
				if fp := compressFiltered(transformE8E9Chunked(e.Data)); fp != nil && len(fp) < len(pack) {
					pack = fp
					method = 3
					filtered = true
				}
			}
			pack, crcVal, extra, err := s.seal(e, pack)
			if err != nil {
				return nil, err
			}
			addHeader(fileHeader(e, pack, method, false, crcVal, extra))
			addData(pack)
			report(e, len(pack), method, filtered)
		}
	}
	addHeader(endHeader())

	var out bytes.Buffer
	out.Write(rarSignature)
	if s.ac != nil {
		out.Write(s.ac.block())
	}
	for _, sg := range segs {
		if s.ac != nil && sg.isHeader {
			enc, err := s.ac.encryptUnit(sg.data)
			if err != nil {
				return nil, err
			}
			out.Write(enc)
		} else {
			out.Write(sg.data)
		}
	}
	return out.Bytes(), nil
}
