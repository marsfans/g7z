package bz3

import (
	"bufio"
	"io"
)

// Writer compresses data into the bzip3 CLI file format.
type Writer struct {
	w         io.Writer
	e         *encoder
	blockSize int
	buf       []byte
	err       error
}

// NewWriter returns a Writer that compresses with blocks of up to
// blockSize bytes (0 selects DefaultBlockSize). The stream header is
// written immediately.
func NewWriter(w io.Writer, blockSize int) (*Writer, error) {
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	if err := checkBlockSize(blockSize); err != nil {
		return nil, err
	}
	wr := &Writer{w: w, e: newEncoder(), blockSize: blockSize}
	var header [9]byte
	copy(header[:], "BZ3v1")
	writeS32(header[5:], int32(blockSize))
	_, wr.err = w.Write(header[:])
	return wr, wr.err
}

func (w *Writer) flushBlock(data []byte) error {
	payload := w.e.encodeBlock(data)
	var chunkHeader [8]byte
	writeS32(chunkHeader[0:], int32(len(payload)))
	writeS32(chunkHeader[4:], int32(len(data)))
	if _, err := w.w.Write(chunkHeader[:]); err != nil {
		return err
	}
	_, err := w.w.Write(payload)
	return err
}

// Write buffers p and encodes a block whenever blockSize bytes have
// accumulated.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.blockSize {
		if err := w.flushBlock(w.buf[:w.blockSize]); err != nil {
			w.err = err
			return 0, err
		}
		w.buf = w.buf[w.blockSize:]
	}
	return len(p), nil
}

// Close flushes the final partial block, if any.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if len(w.buf) > 0 {
		w.err = w.flushBlock(w.buf)
		w.buf = nil
	}
	return w.err
}

// Reader decompresses a bzip3 stream in the CLI file format.
type Reader struct {
	br        *bufio.Reader
	d         *decoder
	blockSize int
	cur       []byte
	off       int
	done      bool
}

// NewReader returns a Reader for a bzip3 stream; the header is parsed
// and validated immediately.
func NewReader(r io.Reader) (*Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	header := make([]byte, 9)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, ErrMalformedHeader
	}
	if string(header[:5]) != "BZ3v1" {
		return nil, ErrMalformedHeader
	}
	blockSize := int(readS32(header[5:]))
	if err := checkBlockSize(blockSize); err != nil {
		return nil, err
	}
	return &Reader{br: br, d: newDecoder(), blockSize: blockSize}, nil
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	for r.off >= len(r.cur) {
		if r.done {
			return 0, io.EOF
		}
		if err := r.nextBlock(); err != nil {
			r.done = true
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	n := copy(p, r.cur[r.off:])
	r.off += n
	return n, nil
}

func (r *Reader) nextBlock() error {
	chunkHeader := make([]byte, 8)
	if _, err := io.ReadFull(r.br, chunkHeader); err != nil {
		if err == io.EOF {
			return io.EOF
		}
		return ErrTruncatedData
	}
	compSize := int(readS32(chunkHeader))
	origSize := int(readS32(chunkHeader[4:]))
	if compSize < 0 || compSize > bound(r.blockSize) || origSize < 0 || origSize > r.blockSize {
		return ErrMalformedHeader
	}
	payload := make([]byte, compSize)
	if _, err := io.ReadFull(r.br, payload); err != nil {
		return ErrTruncatedData
	}
	block, err := r.d.decodeBlock(payload, origSize, r.blockSize)
	if err != nil {
		return err
	}
	r.cur = block
	r.off = 0
	return nil
}

// Close implements io.Closer; it does not close the underlying reader.
func (r *Reader) Close() error { return nil }
