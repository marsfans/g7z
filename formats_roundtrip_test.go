package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestISO_CAB_WIM_Roundtrip drives the format dispatch
// (createArchive/walkArchive) for the three formats added last:
// a small tree must survive a write/read cycle byte-exactly.
// CAB has no directory entries, so only files are compared
// there; ISO and WIM must also keep the empty directory.
func TestISO_CAB_WIM_Roundtrip(t *testing.T) {
	src := t.TempDir()
	contents := map[string][]byte{
		"tree/hello.txt":     bytes.Repeat([]byte("Hello formats!\n"), 50),
		"tree/sub/data.bin":  bytes.Repeat([]byte{1, 2, 3, 4}, 25000),
		"tree/sub/text.txt":  bytes.Repeat([]byte("pack my box with five dozen liquor jugs. "), 300),
		"tree/empty.txt":     {},
		"tree/long name.txt": []byte("long name content"),
	}
	var inputs []*InputFile
	add := func(name string, isDir bool) {
		p := filepath.Join(src, filepath.FromSlash(name))
		if isDir {
			if err := os.MkdirAll(p, 0755); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, contents[name], 0644); err != nil {
				t.Fatal(err)
			}
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, &InputFile{
			Name:    name,
			Path:    p,
			Size:    st.Size(),
			ModTime: st.ModTime(),
			Mode:    st.Mode(),
			IsDir:   isDir,
		})
	}
	add("tree", true)
	add("tree/sub", true)
	add("tree/emptydir", true)
	for name := range contents {
		add(name, false)
	}

	cases := []struct {
		format  string
		level   int
		wantDir bool
	}{
		{"iso", 0, true},
		{"cab", 0, false},
		{"cab", 5, false},
		{"cab", 9, false}, // LZX
		{"wim", 0, true},
		{"wim", 5, true}, // XPRESS
	}
	for _, tc := range cases {
		fm, err := formatByName(tc.format)
		if err != nil {
			t.Fatalf("format %s not registered: %v", tc.format, err)
		}
		arc := filepath.Join(t.TempDir(), "out."+tc.format)
		opt := AddOptions{Format: fm, Level: tc.level}
		if err := createArchive(arc, inputs, opt, NewProgress("", 0)); err != nil {
			t.Fatalf("%s level %d: create: %v", tc.format, tc.level, err)
		}
		got := map[string][]byte{}
		dirs := map[string]bool{}
		err = walkArchive(arc, fm, "", func(e *Entry, open func() (io.ReadCloser, error)) error {
			if e.IsDir {
				dirs[e.Name] = true
				return nil
			}
			rc, err := open()
			if err != nil {
				return err
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return err
			}
			got[e.Name] = data
			return nil
		})
		if err != nil {
			t.Fatalf("%s level %d: walk: %v", tc.format, tc.level, err)
		}
		for name, want := range contents {
			if !bytes.Equal(got[name], want) {
				t.Fatalf("%s level %d: %s content mismatch", tc.format, tc.level, name)
			}
		}
		if tc.wantDir && !dirs["tree/emptydir"] {
			t.Fatalf("%s level %d: empty directory lost", tc.format, tc.level)
		}
	}
}
