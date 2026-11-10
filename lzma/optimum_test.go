package lzma_test

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsfans/g7z/lzma"
)

func compress2(t *testing.T, cfg lzma.Writer2Config, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := cfg.NewWriter2(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decompress2(t *testing.T, comp []byte) []byte {
	t.Helper()
	r, err := lzma.NewReader2(bytes.NewReader(comp))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOptimalRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	random := make([]byte, 100000)
	rng.Read(random)
	words := []string{"the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog"}
	var text bytes.Buffer
	for text.Len() < 300000 {
		text.WriteString(words[rng.Intn(len(words))])
		text.WriteByte(' ')
	}
	cases := map[string][]byte{
		"empty":  {},
		"one":    {0xAB},
		"small":  []byte("hello world, hello lzma, hello optimal parsing"),
		"random": random,
		"text":   text.Bytes(),
		"zeros":  make([]byte, 1<<20),
	}
	cfgs := map[string]lzma.Writer2Config{
		"fast":    {DictCap: 1 << 20},
		"opt32":   {DictCap: 1 << 20, Optimal: true, NiceLen: 32, Depth: 32},
		"opt273":  {DictCap: 1 << 20, Optimal: true, NiceLen: 273, Depth: 128},
		"optDict": {DictCap: 256 << 10, Optimal: true, NiceLen: 64, Depth: 64},
	}
	for cname, cfg := range cfgs {
		for dname, data := range cases {
			comp := compress2(t, cfg, data)
			out := decompress2(t, comp)
			if !bytes.Equal(out, data) {
				t.Errorf("%s/%s: roundtrip mismatch: %d -> %d -> %d bytes",
					cname, dname, len(data), len(comp), len(out))
			}
		}
	}
}

func TestOptimalWriter1Roundtrip(t *testing.T) {
	data := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 5000)
	for _, cfg := range []lzma.WriterConfig{
		{DictCap: 1 << 20},
		{DictCap: 1 << 20, Optimal: true, NiceLen: 64, Depth: 64},
	} {
		var buf bytes.Buffer
		w, err := cfg.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := lzma.NewReader(&buf)
		if err != nil {
			t.Fatal(err)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatalf("writer1 roundtrip mismatch (optimal=%v)", cfg.Optimal)
		}
	}
}

// TestOptimalCorpusSizes is a manual benchmark, enabled with
// LZMA_BENCH_CORPUS=<dir> pointing at a directory of sample files.
func TestOptimalCorpusSizes(t *testing.T) {
	dir := os.Getenv("LZMA_BENCH_CORPUS")
	if dir == "" {
		t.Skip("set LZMA_BENCH_CORPUS")
	}
	for _, name := range []string{"text16.bin", "go.bin"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []struct {
			label string
			cfg   lzma.Writer2Config
		}{
			{"ht4-32M", lzma.Writer2Config{DictCap: 32 << 20}},
			{"opt-n64-d64", lzma.Writer2Config{DictCap: 32 << 20, Optimal: true, NiceLen: 64, Depth: 64}},
			{"opt-n273-d128", lzma.Writer2Config{DictCap: 32 << 20, Optimal: true, NiceLen: 273, Depth: 128}},
		} {
			t0 := time.Now()
			comp := compress2(t, cfg.cfg, data)
			el := time.Since(t0)
			out := decompress2(t, comp)
			if !bytes.Equal(out, data) {
				t.Fatalf("%s %s: roundtrip mismatch", name, cfg.label)
			}
			t.Logf("%s %-14s -> %9d B  %6.2f s", name, cfg.label, len(comp), el.Seconds())
		}
	}
}
