package bz3

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCRCTableMatchesReference pins the generated CRC table against
// values from the table embedded in libbz3.c.
func TestCRCTableMatchesReference(t *testing.T) {
	if crc32Table[1] != 0xF26B8303 || crc32Table[2] != 0xE13B70F7 || crc32Table[255] != 0xAD7D5351 {
		t.Fatalf("crc table mismatch: [1]=%08x [2]=%08x [255]=%08x",
			crc32Table[1], crc32Table[2], crc32Table[255])
	}
}

// TestRoundTrip compresses each testdata original at several block
// sizes and checks the decoder restores it exactly.
func TestRoundTrip(t *testing.T) {
	originals, _ := filepath.Glob("testdata/*.bin")
	for _, origPath := range originals {
		if origPath == "testdata/big.bin" {
			continue // covered by the 1 MiB block sizes below anyway
		}
		data, err := os.ReadFile(origPath)
		if err != nil {
			t.Fatalf("read %s: %v", origPath, err)
		}
		for _, bs := range []int{MinBlockSize, 1 << 20, DefaultBlockSize} {
			comp, err := CompressBytes(data, bs)
			if err != nil {
				t.Fatalf("%s bs=%d: compress: %v", origPath, bs, err)
			}
			got, err := DecompressBytes(comp)
			if err != nil {
				t.Fatalf("%s bs=%d: decompress: %v", origPath, bs, err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("%s bs=%d: round trip mismatch (%d vs %d bytes)", origPath, bs, len(got), len(data))
			}
		}
	}
	// Multi-block: big.bin at 1 MiB blocks.
	data, err := os.ReadFile("testdata/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	comp, err := CompressBytes(data, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecompressBytes(comp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("big.bin multi-block round trip mismatch")
	}
}

// TestBWTForwardInverse checks the BWT pair on assorted inputs,
// including the all-same-byte worst case for suffix sorting.
func TestBWTForwardInverse(t *testing.T) {
	cases := [][]byte{
		[]byte("banana"),
		[]byte("mississippi"),
		bytes.Repeat([]byte("a"), 1000),
		bytes.Repeat([]byte("ab"), 500),
		[]byte{0, 1, 2, 3, 255, 254, 0, 0},
	}
	for _, data := range cases {
		L, idx := bwtForward(data)
		back, err := inverseBWT(L, idx)
		if err != nil {
			t.Fatalf("%q: inverse: %v", data[:8], err)
		}
		if !bytes.Equal(back, data) {
			t.Errorf("BWT round trip mismatch for input starting %q", data[:8])
		}
	}
}

// TestDecodeOfficialVectors decodes every .bz3 file in testdata that was
// produced by the official bzip3 CLI and compares against the original.
func TestDecodeOfficialVectors(t *testing.T) {
	files, err := filepath.Glob("testdata/*.bz3")
	if err != nil || len(files) == 0 {
		t.Fatalf("no test vectors: %v", err)
	}
	for _, f := range files {
		origPath := f[:len(f)-len(".bz3")]
		origPath = origPath[:len(origPath)-len(".bin")] + ".bin"
		// testdata pairs: X.bin (original) and X.bin.bz3, plus the
		// special big1m.bin.bz3 whose original is big.bin.
		if filepath.Base(f) == "big1m.bin.bz3" {
			origPath = "testdata/big.bin"
		}
		want, err := os.ReadFile(origPath)
		if err != nil {
			t.Fatalf("%s: read original: %v", f, err)
		}
		comp, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: read compressed: %v", f, err)
		}
		got, err := DecompressBytes(comp)
		if err != nil {
			t.Errorf("%s: decode error: %v", f, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: decoded %d bytes, want %d, content differs", f, len(got), len(want))
		}
	}
}
