package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	cpiopkg "github.com/marsfans/g7z/cpio"
)

// walkAr lists the members of an ar archive (also the container format
// of .deb packages). Members are exposed as plain files; name handling
// covers the System V, GNU long-name and BSD long-name variants.
func walkAr(path string, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	global := make([]byte, 8)
	if _, err := io.ReadFull(f, global); err != nil || string(global) != "!<arch>\n" {
		return fmt.Errorf("不是 ar 归档: %s", path)
	}

	var nameTable []byte
	for off := int64(8); off+60 <= st.Size(); {
		raw := make([]byte, 60)
		if _, err := f.ReadAt(raw, off); err != nil {
			return fmt.Errorf("ar 头部截断: %s", path)
		}
		if raw[58] != '`' || raw[59] != '\n' {
			return fmt.Errorf("ar 头部损坏: %s", path)
		}
		parseDec := func(b []byte) int64 {
			v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
			return v
		}
		name := strings.TrimSpace(string(raw[0:16]))
		mtime := parseDec(raw[16:28])
		mode64, _ := strconv.ParseUint(strings.TrimSpace(string(raw[40:48])), 8, 32)
		size := parseDec(raw[48:58])
		dataOff := off + 60
		memberSize := size
		emit := true

		switch {
		case name == "/" || name == "/SYM64/":
			emit = false // symbol table
		case name == "//":
			emit = false // GNU long-name table
			nameTable = make([]byte, size)
			if _, err := f.ReadAt(nameTable, dataOff); err != nil {
				return fmt.Errorf("ar 长名表截断: %s", path)
			}
		case strings.HasPrefix(name, "/"):
			idx, err := strconv.Atoi(name[1:])
			if err != nil || idx < 0 || idx >= len(nameTable) {
				return fmt.Errorf("ar 长名引用无效: %q", name)
			}
			end := idx
			for end < len(nameTable) && nameTable[end] != '\n' {
				end++
			}
			name = strings.TrimSuffix(string(nameTable[idx:end]), "/")
		case strings.HasPrefix(name, "#1/"):
			n, err := strconv.Atoi(name[3:])
			if err != nil || int64(n) > size {
				return fmt.Errorf("ar BSD 长名无效: %q", name)
			}
			nb := make([]byte, n)
			if _, err := f.ReadAt(nb, dataOff); err != nil {
				return fmt.Errorf("ar BSD 长名截断: %s", path)
			}
			name = string(nb)
			dataOff += int64(n)
			memberSize -= int64(n)
		default:
			name = strings.TrimSuffix(name, "/")
		}

		if emit {
			mh := cpiopkg.Header{Mode: uint32(mode64)}
			e := &Entry{
				Name:    name,
				Size:    memberSize,
				Packed:  memberSize,
				ModTime: time.Unix(mtime, 0),
				Mode:    mh.FileMode(),
			}
			mo, ms := dataOff, memberSize
			if err := fn(e, func() (io.ReadCloser, error) {
				return io.NopCloser(io.NewSectionReader(f, mo, ms)), nil
			}); err != nil {
				return err
			}
		}
		// Advance from the member's header start by header + declared
		// size (+1 pad byte for odd sizes), independent of BSD name
		// adjustments to dataOff.
		off += 60 + size + (size & 1)
	}
	return nil
}
