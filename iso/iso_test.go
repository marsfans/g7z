package iso

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// TestISORoundtrip writes an image with the tricky cases — long
// names that spill into a SUSP continuation area, names past
// 250 bytes (split NM entries), mangling collisions, an empty
// directory and a directory spanning several blocks — and reads
// it back with the package reader.
func TestISORoundtrip(t *testing.T) {
	mt := time.Date(2024, 3, 5, 12, 30, 45, 0, time.UTC)
	mk := func(name string, data string) *Entry {
		return &Entry{
			Name:    name,
			Size:    int64(len(data)),
			ModTime: mt,
			Mode:    0640,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(data)), nil
			},
		}
	}
	longName := strings.Repeat("n", 200) + ".txt"
	hugeName := strings.Repeat("m", 251) + ".bin"
	files := []*Entry{
		{Name: "tree", IsDir: true, ModTime: mt, Mode: 0755},
		{Name: "tree/emptydir", IsDir: true, ModTime: mt, Mode: 0755},
		mk("tree/hello.txt", "hello"),
		mk("tree/long file name with spaces.md", "spaces"),
		mk("tree/"+longName, "long"),
		mk("tree/"+hugeName, "huge"),
		mk("tree/a b.txt", "space name"),
		mk("tree/a_b.txt", "underscore name"),
		mk("tree/A B.TXT", "upper name"),
		mk("tree/empty.txt", ""),
	}
	for i := 0; i < 300; i++ {
		files = append(files, mk(fmt.Sprintf("tree/many/file_%03d.dat", i), "x"))
	}

	var buf bytes.Buffer
	if err := Create(&buf, "TESTVOL", files); err != nil {
		t.Fatal(err)
	}
	rd, err := Open(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*File{}
	var walk func(d *File, prefix string) error
	walk = func(d *File, prefix string) error {
		children, err := d.Children()
		if err != nil {
			return err
		}
		for _, c := range children {
			p := prefix + c.Name
			got[p] = c
			if c.IsDir {
				if err := walk(c, p+"/"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(rd.Root(), ""); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"tree/hello.txt":                     "hello",
		"tree/long file name with spaces.md": "spaces",
		"tree/" + longName:                   "long",
		"tree/" + hugeName:                   "huge",
		"tree/a b.txt":                       "space name",
		"tree/a_b.txt":                       "underscore name",
		"tree/A B.TXT":                       "upper name",
		"tree/empty.txt":                     "",
		"tree/many/file_000.dat":             "x",
		"tree/many/file_299.dat":             "x",
	}
	for path, content := range want {
		f, ok := got[path]
		if !ok {
			t.Fatalf("missing %s (have %d entries)", path, len(got))
		}
		data, err := io.ReadAll(f.Open())
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != content {
			t.Fatalf("%s: content %q, want %q", path, data, content)
		}
		if f.Mode.Perm() != 0640 {
			t.Fatalf("%s: mode %v, want 0640", path, f.Mode)
		}
		if !f.ModTime.Equal(mt) {
			t.Fatalf("%s: mtime %v, want %v", path, f.ModTime, mt)
		}
	}
	if d, ok := got["tree/emptydir"]; !ok || !d.IsDir {
		t.Fatal("empty directory lost")
	}
	// tree + emptydir + many dirs, 8 tree files, 300 many files.
	if want := 3 + 8 + 300; len(got) != want {
		t.Fatalf("entry count %d, want %d", len(got), want)
	}
}
