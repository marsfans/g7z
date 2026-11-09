package main

// x86 BCJ 过滤器编码器（7z coder 0x03030103）。
// 算法忠实移植 Igor Pavlov 的 Bra86.c（公共领域，2017-04-03 版），
// 只使用 encoding=true 分支；跨缓冲区状态经 mask 保留，与官方实现一致。

import "io"

func test86MSByte(b byte) bool { return (b+1)&0xFE == 0 }

type bcjX86Writer struct {
	w    io.Writer
	buf  []byte // 未处理数据（含跨块状态相关的尾部）
	mask uint32 // Bra86 的 *state & 7
	ip   uint32 // 流内位置（低 32 位）
}

func newBCJX86Writer(w io.Writer) *bcjX86Writer {
	return &bcjX86Writer{w: w}
}

// convert 对 buf[:size] 做 BCJ x86 转换，返回已处理字节数（其余留给下次）。
func (b *bcjX86Writer) convert(data []byte, size int) int {
	pos := 0
	mask := b.mask & 7
	if size < 5 {
		return 0
	}
	limitSize := size - 4
	ip := b.ip + 5
	for {
		p := pos
		for p < limitSize && (data[p]&0xFE) != 0xE8 {
			p++
		}
		d := p - pos
		pos = p
		if p >= limitSize {
			if d > 2 {
				b.mask = 0
			} else {
				b.mask = mask >> uint(d)
			}
			return pos
		}
		if d > 2 {
			mask = 0
		} else {
			mask >>= uint(d)
			if mask != 0 && (mask > 4 || mask == 3 || test86MSByte(data[p+int(mask>>1)+1])) {
				mask = (mask >> 1) | 4
				pos++
				continue
			}
		}
		if test86MSByte(data[p+4]) {
			v := uint32(data[p+4])<<24 | uint32(data[p+3])<<16 | uint32(data[p+2])<<8 | uint32(data[p+1])
			cur := ip + uint32(pos)
			pos += 5
			v += cur // encoding = true
			if mask != 0 {
				sh := (mask & 6) << 2
				if test86MSByte(byte(v >> sh)) {
					v ^= (uint32(0x100) << sh) - 1
					v += cur
				}
				mask = 0
			}
			data[p+1] = byte(v)
			data[p+2] = byte(v >> 8)
			data[p+3] = byte(v >> 16)
			data[p+4] = byte(0 - ((v >> 24) & 1))
		} else {
			mask = (mask >> 1) | 4
			pos++
		}
	}
}

func (b *bcjX86Writer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	n := b.convert(b.buf, len(b.buf))
	b.ip += uint32(n)
	if n > 0 {
		if _, err := b.w.Write(b.buf[:n]); err != nil {
			return 0, err
		}
		b.buf = append(b.buf[:0], b.buf[n:]...)
	}
	return len(p), nil
}

// Close 冲刷尾部：最后 <5 字节按官方实现不做转换，原样写出。
func (b *bcjX86Writer) Close() error {
	n := b.convert(b.buf, len(b.buf))
	b.ip += uint32(n)
	if _, err := b.w.Write(b.buf); err != nil {
		return err
	}
	b.buf = nil
	return nil
}
