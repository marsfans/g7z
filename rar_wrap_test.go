package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsfans/g7z/rarpack"
	"github.com/nwaples/rardecode/v2"
)

// Regression test for the rardecode window-wrap truncation fixed upstream
// in v2.4.6: decodeReader.copyBytes dropped the part of an LZ match that
// straddled the end of the sliding window, so a solid archive whose
// decoded stream exceeds the 16 MiB dictionary lost bytes mid-stream
// (files after the crossing then failed with "bad file checksum").
// Period-45 data compresses to maximum-length matches at distance 45;
// with ~18 MB in one solid stream one of those matches straddles the
// window boundary.
func TestRARSolidWindowWrapRoundTrip(t *testing.T) {
	pat := make([]byte, 45)
	for i := range pat {
		pat[i] = byte(i*7 + 3)
	}
	mk := func(n, phase int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = pat[(i+phase)%len(pat)]
		}
		return b
	}
	want := map[string][]byte{
		"a.bin": mk(15_500_000, 0),
		"b.bin": mk(2_500_000, 15_500_000%len(pat)),
	}

	arc := filepath.Join(t.TempDir(), "wrap.rar")
	f, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	w := rarpack.NewWriter(f, &rarpack.Options{Solid: true})
	for _, name := range []string{"a.bin", "b.bin"} {
		if err := w.Add(name, want[name], time.Unix(1700000000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := rardecode.OpenReader(arc)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		if !bytes.Equal(got, want[h.Name]) {
			t.Fatalf("%s: decoded %d bytes, want %d (content differs or truncated)",
				h.Name, len(got), len(want[h.Name]))
		}
	}
}
