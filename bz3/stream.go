package bz3

import (
	"bufio"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// Blocks are compressed independently, so a stream can be encoded and
// decoded block-parallel while emitting results in stream order. The
// output bytes do not depend on the worker count.

var errWriterClosed = errors.New("bz3: writer already closed")

// defaultWorkers picks the worker count when none is requested.
func defaultWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

type blockJob struct {
	seq  int
	data []byte // raw block for encoding, payload for decoding
	orig int    // decode only: expected decompressed size
}

type blockResult struct {
	seq     int
	payload []byte // encoded payload or decoded block
	orig    int    // encode only: raw block size (chunk header field)
	err     error  // decode only
}

// Writer compresses data into the bzip3 CLI file format, encoding
// blocks concurrently and writing them in order.
type Writer struct {
	w         io.Writer
	blockSize int

	encPool  sync.Pool
	jobs     chan blockJob
	results  chan blockResult
	emitDone chan struct{}
	err      atomic.Value // error

	mu     sync.Mutex // guards buf, seq, closed
	buf    []byte
	seq    int
	closed bool
}

// NewWriter returns a Writer that compresses with blocks of up to
// blockSize bytes (0 selects DefaultBlockSize), using a default number
// of worker goroutines. The stream header is written immediately.
func NewWriter(w io.Writer, blockSize int) (*Writer, error) {
	return NewWriterWorkers(w, blockSize, 0)
}

// NewWriterWorkers is NewWriter with an explicit worker count
// (values <= 0 select the default).
func NewWriterWorkers(w io.Writer, blockSize, workers int) (*Writer, error) {
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	if err := checkBlockSize(blockSize); err != nil {
		return nil, err
	}
	if workers <= 0 {
		workers = defaultWorkers()
	}
	wr := &Writer{
		w:         w,
		blockSize: blockSize,
		encPool:   sync.Pool{New: func() any { return newEncoder() }},
		jobs:      make(chan blockJob, workers*2),
		results:   make(chan blockResult, workers*2),
		emitDone:  make(chan struct{}),
	}
	var header [9]byte
	copy(header[:], "BZ3v1")
	writeS32(header[5:], int32(blockSize))
	if _, err := w.Write(header[:]); err != nil {
		wr.setErr(err)
		close(wr.emitDone)
		return wr, err
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range wr.jobs {
				e := wr.encPool.Get().(*encoder)
				payload := e.encodeBlock(j.data)
				wr.encPool.Put(e)
				wr.results <- blockResult{seq: j.seq, payload: payload, orig: len(j.data)}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(wr.results)
	}()
	go wr.emit()
	return wr, nil
}

// emit writes encoded blocks to the underlying writer in stream order.
func (w *Writer) emit() {
	defer close(w.emitDone)
	next := 0
	pending := make(map[int]blockResult)
	for r := range w.results {
		pending[r.seq] = r
		for {
			pr, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			if w.getErr() != nil {
				continue // drain without writing after a failure
			}
			var chunkHeader [8]byte
			writeS32(chunkHeader[0:], int32(len(pr.payload)))
			writeS32(chunkHeader[4:], int32(pr.orig))
			if _, err := w.w.Write(chunkHeader[:]); err != nil {
				w.setErr(err)
				continue
			}
			if _, err := w.w.Write(pr.payload); err != nil {
				w.setErr(err)
			}
		}
	}
}

func (w *Writer) setErr(err error) {
	if w.err.Load() == nil {
		w.err.Store(err)
	}
}

func (w *Writer) getErr() error {
	if v := w.err.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// Write buffers p and encodes a block whenever blockSize bytes have
// accumulated.
func (w *Writer) Write(p []byte) (int, error) {
	if err := w.getErr(); err != nil {
		return 0, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errWriterClosed
	}
	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.blockSize {
		block := w.buf[:w.blockSize:w.blockSize]
		w.buf = w.buf[w.blockSize:]
		w.jobs <- blockJob{seq: w.seq, data: block}
		w.seq++
	}
	return len(p), nil
}

// Close flushes the final partial block, if any, and waits for all
// blocks to be written out.
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return w.getErr()
	}
	w.closed = true
	rest := w.buf
	w.buf = nil
	w.mu.Unlock()

	if w.getErr() == nil && len(rest) > 0 {
		w.jobs <- blockJob{seq: w.seq, data: rest}
		w.seq++
	}
	close(w.jobs)
	<-w.emitDone
	return w.getErr()
}

// readerBlock is one ordered unit delivered to Reader.Read.
type readerBlock struct {
	data []byte
	err  error
}

// Reader decompresses a bzip3 stream in the CLI file format, decoding
// blocks concurrently while delivering them in order.
type Reader struct {
	br        *bufio.Reader
	blockSize int

	blocks chan readerBlock
	quit   chan struct{}
	once   sync.Once

	cur []byte
	off int
	err error // sticky terminal error
}

// NewReader returns a Reader for a bzip3 stream; the header is parsed
// and validated immediately.
func NewReader(r io.Reader) (*Reader, error) {
	return NewReaderWorkers(r, 0)
}

// NewReaderWorkers is NewReader with an explicit worker count
// (values <= 0 select the default).
func NewReaderWorkers(r io.Reader, workers int) (*Reader, error) {
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
	if workers <= 0 {
		workers = defaultWorkers()
	}
	rd := &Reader{
		br:        br,
		blockSize: blockSize,
		blocks:    make(chan readerBlock, workers*2),
		quit:      make(chan struct{}),
	}
	jobs := make(chan blockJob, workers*2)
	results := make(chan blockResult, workers*2)
	done := make(chan error, 1)
	decPool := &sync.Pool{New: func() any { return newDecoder() }}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				d := decPool.Get().(*decoder)
				block, err := d.decodeBlock(j.data, j.orig, blockSize)
				decPool.Put(d)
				select {
				case results <- blockResult{seq: j.seq, payload: block, err: err}:
				case <-rd.quit:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	go rd.produce(jobs, done)
	go rd.collect(results, done)
	return rd, nil
}

// produce reads chunk payloads from the stream and dispatches them to
// the decode workers. It reports the terminal read error (nil for a
// clean end of stream) on done.
func (r *Reader) produce(jobs chan<- blockJob, done chan<- error) {
	seq := 0
	var readErr error
	chunkHeader := make([]byte, 8)
loop:
	for {
		if _, err := io.ReadFull(r.br, chunkHeader); err != nil {
			if err != io.EOF {
				readErr = ErrTruncatedData
			}
			break
		}
		compSize := int(readS32(chunkHeader))
		origSize := int(readS32(chunkHeader[4:]))
		if compSize < 0 || compSize > bound(r.blockSize) || origSize < 0 || origSize > r.blockSize {
			readErr = ErrMalformedHeader
			break
		}
		payload := make([]byte, compSize)
		if _, err := io.ReadFull(r.br, payload); err != nil {
			readErr = ErrTruncatedData
			break
		}
		select {
		case jobs <- blockJob{seq: seq, data: payload, orig: origSize}:
			seq++
		case <-r.quit:
			break loop
		}
	}
	close(jobs)
	done <- readErr
}

// collect forwards decoded blocks to r.blocks in stream order. The
// first error (a block decode error, else the producer's read error)
// is delivered as a final block after all preceding data.
func (r *Reader) collect(results <-chan blockResult, done <-chan error) {
	defer close(r.blocks)
	emit := func(b readerBlock) bool {
		select {
		case r.blocks <- b:
			return true
		case <-r.quit:
			return false
		}
	}
	next := 0
	pending := make(map[int]blockResult)
	var firstErr error
	for res := range results {
		pending[res.seq] = res
		for {
			pr, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			switch {
			case firstErr != nil:
				// Keep draining; the error is delivered at the end.
			case pr.err != nil:
				firstErr = pr.err
			default:
				if !emit(readerBlock{data: pr.payload}) {
					return
				}
			}
		}
	}
	if firstErr == nil {
		firstErr = <-done
	} else {
		<-done
	}
	if firstErr != nil {
		emit(readerBlock{err: firstErr})
	}
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	for r.off >= len(r.cur) {
		if r.err != nil {
			return 0, r.err
		}
		blk, ok := <-r.blocks
		if !ok {
			return 0, io.EOF
		}
		if blk.err != nil {
			r.err = blk.err
			return 0, r.err
		}
		if len(blk.data) == 0 {
			continue
		}
		r.cur = blk.data
		r.off = 0
	}
	n := copy(p, r.cur[r.off:])
	r.off += n
	return n, nil
}

// Close implements io.Closer; it stops the background pipeline and does
// not close the underlying reader.
func (r *Reader) Close() error {
	r.once.Do(func() { close(r.quit) })
	return nil
}
