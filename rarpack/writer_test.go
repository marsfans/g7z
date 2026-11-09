package rarpack

import (
	"bytes"
	"hash/crc32"
	"testing"
	"time"
)

// Minimal RAR5 header walk to validate Writer output structure:
// names, unpacked sizes, CRC32s and data areas must line up.
func TestWriterRoundTripStructure(t *testing.T) {
	entries := []Entry{
		{Name: "a.txt", Data: []byte("hello world, hello rar5, hello hello hello"), ModTime: time.Unix(1700000000, 0)},
		{Name: "b.bin", Data: bytes.Repeat([]byte{1, 2, 3, 4}, 5000), ModTime: time.Unix(1700000001, 0)},
		{Name: "empty", Data: nil, ModTime: time.Unix(1700000002, 0)},
	}
	var buf bytes.Buffer
	if err := Archive(&buf, nil, entries); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.Equal(out[:8], rarSignature) {
		t.Fatal("bad signature")
	}
	// Walk headers with a small vint reader.
	pos := 8
	readVint := func() uint64 {
		var v uint64
		var s uint
		for {
			b := out[pos]
			pos++
			v |= uint64(b&0x7f) << s
			s += 7
			if b&0x80 == 0 {
				return v
			}
		}
	}
	seen := 0
	for pos < len(out) {
		pos += 4 // head CRC, verified implicitly by unrar in e2e checks
		hsize := int(readVint())
		hdrStart := pos
		htype := readVint()
		hflags := readVint()
		var dsize uint64
		if hflags&1 != 0 {
			readVint()
		}
		if hflags&2 != 0 {
			dsize = readVint()
		}
		if htype == 2 {
			ff := readVint()
			usize := readVint()
			readVint() // attr
			if ff&2 != 0 {
				pos += 4
			}
			var crc uint32
			if ff&4 != 0 {
				crc = uint32(out[pos]) | uint32(out[pos+1])<<8 | uint32(out[pos+2])<<16 | uint32(out[pos+3])<<24
				pos += 4
			}
			readVint() // comp info
			readVint() // host os
			nl := readVint()
			name := string(out[pos : pos+int(nl)])
			pos += int(nl)
			e := entries[seen]
			if name != e.Name || int(usize) != len(e.Data) || crc != crc32.ChecksumIEEE(e.Data) {
				t.Fatalf("entry %d mismatch: %q %d %08x", seen, name, usize, crc)
			}
			seen++
		}
		pos = hdrStart + hsize + int(dsize)
		if htype == 5 {
			break
		}
	}
	if seen != len(entries) {
		t.Fatalf("saw %d of %d entries", seen, len(entries))
	}
}

func TestHeaderEncryptionHidesNames(t *testing.T) {
	var buf bytes.Buffer
	err := Archive(&buf, &Options{Password: "pw", HeaderEncryption: true},
		[]Entry{{Name: "secret-name.txt", Data: []byte("hello hello hello hello")}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("secret-name.txt")) {
		t.Fatal("file name visible in header-encrypted archive")
	}
	if err := Archive(&buf, &Options{HeaderEncryption: true}, nil); err == nil {
		t.Fatal("expected error for HeaderEncryption without Password")
	}
}
