package rarpack

import (
	"bytes"
	"os"
	"testing"
)

// Simulate decoding from tokens alone (no bitstream): catches matcher /
// tokenizer bugs independently of Huffman/table serialization.
func TestTokenSimulation(t *testing.T) {
	files := []string{"../extracted/Zip32.SFX", "../extracted/Default32.SFX", "../extracted/WinRAR.exe", "../extracted/Rar.exe"}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Skip(f)
		}
		m := newMatcher(data)
		st := &streamState{}
		var out []byte
		for start := 0; start < len(data); start += blockData {
			end := start + blockData
			if end > len(data) {
				end = len(data)
			}
			toks := tokenizeBlock(m, st, start, end)
			for _, tk := range toks {
				if !tk.match {
					out = append(out, tk.lit)
				} else {
					if tk.dist <= 0 || tk.dist > len(out) {
						t.Fatalf("%s: bad dist %d at out pos %d", f, tk.dist, len(out))
					}
					for i := 0; i < tk.length; i++ {
						out = append(out, out[len(out)-tk.dist])
					}
				}
			}
			if len(out) != end {
				t.Fatalf("%s: after block [%d,%d) out len %d", f, start, end, len(out))
			}
		}
		if !bytes.Equal(out, data) {
			i := 0
			for i < len(data) && out[i] == data[i] {
				i++
			}
			t.Fatalf("%s: token simulation diverges at %d (block %d)", f, i, i/blockData)
		}
	}
}
