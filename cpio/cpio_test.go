package cpio

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"
)

// readAllEntries parses a whole archive into headers + data.
func readAllEntries(t *testing.T, path string) ([]*Header, [][]byte) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := NewReader(f)
	var hdrs []*Header
	var datas [][]byte
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("%s: Next: %v", path, err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: read %s: %v", path, h.Name, err)
		}
		hdrs = append(hdrs, h)
		datas = append(datas, data)
	}
	return hdrs, datas
}

// TestGNUFixtures decodes archives produced by GNU cpio 2.15 in both
// newc and crc variants, including a symlink and a hard link pair.
func TestGNUFixtures(t *testing.T) {
	hello, _ := os.ReadFile("testdata/hello.txt")
	big, _ := os.ReadFile("testdata/big.bin")
	shared, _ := os.ReadFile("testdata/hard1.txt")
	inner, _ := os.ReadFile("testdata/inner.txt")

	for _, path := range []string{"testdata/gnu.cpio", "testdata/gnu-crc.cpio"} {
		hdrs, datas := readAllEntries(t, path)
		byName := map[string]int{}
		for i, h := range hdrs {
			byName[h.Name] = i
		}
		for _, want := range []string{".", "hello.txt", "empty.bin", "big.bin", "sub/inner.txt", "hard1.txt", "hard2.txt", "link.txt", "sub"} {
			if _, ok := byName[want]; !ok {
				t.Fatalf("%s: missing entry %q (have %v)", path, want, byName)
			}
		}
		check := func(name string, want []byte) {
			i := byName[name]
			if !bytes.Equal(datas[i], want) {
				t.Errorf("%s: %s data mismatch (%d vs %d bytes)", path, name, len(datas[i]), len(want))
			}
		}
		check("hello.txt", hello)
		check("big.bin", big)
		check("sub/inner.txt", inner)

		// Symlink: data is the target.
		li := byName["link.txt"]
		if !hdrs[li].IsSymlink() || string(datas[li]) != "hello.txt" {
			t.Errorf("%s: link.txt: symlink=%v target=%q", path, hdrs[li].IsSymlink(), datas[li])
		}
		// Hard link pair: same inode, exactly one carries the data.
		h1, h2 := byName["hard1.txt"], byName["hard2.txt"]
		if hdrs[h1].Ino != hdrs[h2].Ino || hdrs[h1].Ino == 0 {
			t.Errorf("%s: hardlink inodes differ: %d vs %d", path, hdrs[h1].Ino, hdrs[h2].Ino)
		}
		got1, got2 := datas[h1], datas[h2]
		if len(got1) == 0 && len(got2) != 0 {
			got1, got2 = got2, got1
		}
		if !bytes.Equal(got1, shared) || len(got2) != 0 {
			t.Errorf("%s: hardlink data split wrong: %d and %d bytes", path, len(datas[h1]), len(datas[h2]))
		}
		if !hdrs[byName["sub"]].IsDir() {
			t.Errorf("%s: sub is not a directory", path)
		}
	}
}

// TestRoundTrip writes entries with the Writer and reads them back.
func TestRoundTrip(t *testing.T) {
	mtime := time.Unix(1700000000, 0)
	var buf bytes.Buffer
	w := NewWriter(&buf)
	entries := []struct {
		hdr  *Header
		data []byte
	}{
		{&Header{Name: "dir", Mode: 0o040755, Nlink: 2, ModTime: mtime}, nil},
		{&Header{Name: "dir/file.txt", Mode: 0o100644, Ino: 42, Nlink: 1, ModTime: mtime, Size: 5}, []byte("12345")},
		{&Header{Name: "dir/link", Mode: 0o120777, Nlink: 1, ModTime: mtime, Size: 8}, []byte("file.txt")},
		{&Header{Name: "odd", Mode: 0o100600, Ino: 7, Nlink: 1, ModTime: mtime, Size: 3}, []byte("abc")},
	}
	for _, e := range entries {
		if err := w.WriteHeader(e.hdr); err != nil {
			t.Fatalf("WriteHeader %s: %v", e.hdr.Name, err)
		}
		if len(e.data) > 0 {
			if _, err := w.Write(e.data); err != nil {
				t.Fatalf("Write %s: %v", e.hdr.Name, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.Len()%512 != 0 {
		t.Errorf("archive size %d is not a multiple of 512", buf.Len())
	}

	r := NewReader(&buf)
	for _, want := range entries {
		h, err := r.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if h.Name != want.hdr.Name || h.Mode != want.hdr.Mode || h.Ino != want.hdr.Ino || h.Size != want.hdr.Size {
			t.Errorf("header mismatch: got %+v want %+v", h, want.hdr)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read %s: %v", h.Name, err)
		}
		if !bytes.Equal(data, want.data) {
			t.Errorf("%s: data %q != %q", h.Name, data, want.data)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("final Next: got %v, want EOF", err)
	}
}

// TestCRCCorruption flips a data byte in the crc fixture and expects
// the reader to reject the entry (via a synthetic stream instead of
// editing the fixture).
func TestCRCCorruption(t *testing.T) {
	raw, err := os.ReadFile("testdata/gnu-crc.cpio")
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the byte right after the first header's name padding
	// region of 'hello.txt': find its name in the stream and flip a
	// byte a bit later — simplest: flip the last payload byte of the
	// archive body before the trailer's 512 padding: flip byte at
	// offset of "hello cpio world" text.
	idx := bytes.Index(raw, []byte("hello cpio world"))
	if idx < 0 {
		t.Fatal("payload not found in fixture")
	}
	raw[idx] ^= 0xFF
	r := NewReader(bytes.NewReader(raw))
	var errSeen error
	for {
		_, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			errSeen = err
			break
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			errSeen = err
			break
		}
	}
	if errSeen != ErrChecksum {
		t.Fatalf("got %v, want ErrChecksum", errSeen)
	}
}
