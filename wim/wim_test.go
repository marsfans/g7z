package wim

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWIMRoundtrip writes an image at several levels and reads
// it back: nested directories, an empty directory, an empty
// file, a multi-chunk file (the chunk table's first implicit
// offset is the table size itself — a layout detail strict
// readers depend on) and duplicate content (deduplicated).
func TestWIMRoundtrip(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 8192) // 128 KiB, 4 chunks
	files := []struct {
		name  string
		isDir bool
		data  []byte
	}{
		{"dir", true, nil},
		{"dir/empty-dir", true, nil},
		{"hello.txt", false, bytes.Repeat([]byte("Hello formats!\n"), 50)},
		{"dir/big.bin", false, big},
		{"dir/copy-of-big.bin", false, big},
		{"empty.txt", false, nil},
	}
	for _, level := range []int{0, 5, 9} {
		path := filepath.Join(t.TempDir(), "test.wim")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := NewWriter(f, level)
		mt := time.Unix(1700000000, 0)
		for _, file := range files {
			mode := os.FileMode(0644)
			if file.isDir {
				mode = os.ModeDir | 0755
			}
			if err := w.Add(file.name, mode, mt, file.isDir, file.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		rf, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		st, _ := rf.Stat()
		rd, err := OpenReader(rf, st.Size())
		if err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		entries, err := rd.Image(1)
		if err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		got := map[string]*Entry{}
		for _, e := range entries {
			got[e.Name] = e
		}
		for _, file := range files {
			e, ok := got[file.name]
			if !ok {
				t.Fatalf("level %d: missing entry %s", level, file.name)
			}
			if e.IsDir != file.isDir {
				t.Fatalf("level %d: %s IsDir=%v", level, file.name, e.IsDir)
			}
			if file.isDir {
				continue
			}
			rc, err := rd.Open(e)
			if err != nil {
				t.Fatalf("level %d: open %s: %v", level, file.name, err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("level %d: read %s: %v", level, file.name, err)
			}
			if !bytes.Equal(data, file.data) {
				t.Fatalf("level %d: %s content mismatch (%d vs %d bytes)",
					level, file.name, len(data), len(file.data))
			}
		}
		rf.Close()
	}
}
