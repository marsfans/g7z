package bz3

import (
	"bytes"
	"io"
)

// decoder holds the reusable per-stream decoding state.
type decoder struct {
	cm  cmState
	lut []int32
}

func newDecoder() *decoder {
	return &decoder{lut: make([]int32, 1<<lzpDictionary)}
}

// decodeBlock decodes one block payload (the bytes after the chunk
// header) into its origSize original bytes. blockSize is the stream's
// maximum block size, used for sanity checks like the reference.
func (d *decoder) decodeBlock(payload []byte, origSize, blockSize int) ([]byte, error) {
	if len(payload) < 9 {
		return nil, ErrMalformedHeader
	}
	crc := readS32(payload)
	bwtIdx := readS32(payload[4:])

	if origSize < 0 || origSize > blockSize {
		return nil, ErrMalformedHeader
	}

	// Literal block: bwtIndex == -1, payload is crc + -1 + raw data.
	if bwtIdx == -1 {
		data := payload[8:]
		if len(data) != origSize || origSize > 64 {
			return nil, ErrMalformedHeader
		}
		out := make([]byte, len(data))
		copy(out, data)
		if blockCRC(out) != uint32(crc) {
			return nil, ErrCRC
		}
		return out, nil
	}

	model := payload[8]
	lzpSize, rleSize := -1, -1
	p := 0 // size fields read so far
	if model&2 != 0 {
		if len(payload) < 9+4*(p+1) {
			return nil, ErrMalformedHeader
		}
		lzpSize = int(readS32(payload[9+4*p:]))
		p++
	}
	if model&4 != 0 {
		if len(payload) < 9+4*(p+1) {
			return nil, ErrMalformedHeader
		}
		rleSize = int(readS32(payload[9+4*p:]))
		p++
	}
	p += 2 // crc + bwt index dwords
	headerBytes := p*4 + 1
	if len(payload) < headerBytes {
		return nil, ErrMalformedHeader
	}
	acData := payload[headerBytes:]

	sizeBeforeBWT := origSize
	if model&2 != 0 {
		sizeBeforeBWT = lzpSize
	} else if model&4 != 0 {
		sizeBeforeBWT = rleSize
	}
	if sizeBeforeBWT < 0 || sizeBeforeBWT > bound(blockSize) {
		return nil, ErrMalformedHeader
	}

	// Arithmetic decode, then undo the BWT.
	stage := make([]byte, sizeBeforeBWT)
	d.cm.begin()
	d.cm.decodeBytes(acData, stage)

	stage, err := inverseBWT(stage, int(bwtIdx))
	if err != nil {
		return nil, err
	}

	// Undo LZP, then RLE.
	if model&2 != 0 {
		stage, err = lzpDecode(stage, bound(blockSize), d.lut)
		if err != nil {
			return nil, err
		}
	}
	if model&4 != 0 {
		stage, err = rleDecode(stage, origSize)
		if err != nil {
			return nil, err
		}
	}

	if len(stage) != origSize {
		return nil, ErrMalformedHeader
	}
	if blockCRC(stage) != uint32(crc) {
		return nil, ErrCRC
	}
	return stage, nil
}

// Decompress reads a bzip3 stream in the CLI file format from r and
// writes the decompressed data to w.
func Decompress(w io.Writer, r io.Reader) error {
	rd, err := NewReader(r)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, rd)
	return err
}

// DecompressBytes decompresses a complete in-memory bzip3 stream.
func DecompressBytes(in []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := Decompress(&out, bytes.NewReader(in)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
