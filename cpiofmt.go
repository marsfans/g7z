package main

import (
	"io"
	"os"

	cpiopkg "github.com/marsfans/g7z/cpio"
)

// walkCpio streams a cpio archive. Hard link groups in cpio carry
// their data on the last member, so size-0 members are held back and
// emitted as hard links right after their data-carrying member.
func walkCpio(path, codec string, fn WalkFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rc, err := newDecompressor(codec, f)
	if err != nil {
		return err
	}
	defer rc.Close()
	cr := cpiopkg.NewReader(rc)

	empty := func() (io.ReadCloser, error) { return io.NopCloser(emptyReader{}), nil }
	type groupKey struct{ devMaj, devMin, ino uint32 }
	held := map[groupKey][]*Entry{}
	carrierSeen := map[groupKey]string{}

	for {
		h, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		e := &Entry{Name: h.Name, Size: h.Size, Packed: -1, ModTime: h.ModTime, Mode: h.FileMode(), IsDir: h.IsDir()}
		switch {
		case h.IsSymlink():
			target, err := io.ReadAll(cr)
			if err != nil {
				return err
			}
			e.Link = string(target)
			e.Size = int64(len(target))
			if err := fn(e, empty); err != nil {
				return err
			}
		case h.IsRegular() && h.Nlink > 1 && h.Ino != 0:
			key := groupKey{h.DevMajor, h.DevMinor, h.Ino}
			if h.Size > 0 {
				carrierSeen[key] = h.Name
				if err := fn(e, func() (io.ReadCloser, error) { return io.NopCloser(cr), nil }); err != nil {
					return err
				}
				for _, heldE := range held[key] {
					heldE.Link = h.Name
					heldE.HardLink = true
					if err := fn(heldE, empty); err != nil {
						return err
					}
				}
				delete(held, key)
			} else if carrier, ok := carrierSeen[key]; ok {
				e.Link = carrier
				e.HardLink = true
				if err := fn(e, empty); err != nil {
					return err
				}
			} else {
				held[key] = append(held[key], e)
			}
		case h.IsDir() || h.IsRegular():
			if err := fn(e, func() (io.ReadCloser, error) { return io.NopCloser(cr), nil }); err != nil {
				return err
			}
		default:
			// Device nodes, fifos and sockets are skipped, as in
			// the tar walker.
			continue
		}
	}
	// Groups whose data never appeared (e.g. genuinely empty files):
	// the first held member stands in as the carrier.
	for _, members := range held {
		if len(members) == 0 {
			continue
		}
		carrier := members[0]
		if err := fn(carrier, empty); err != nil {
			return err
		}
		for _, m := range members[1:] {
			m.Link = carrier.Name
			m.HardLink = true
			if err := fn(m, empty); err != nil {
				return err
			}
		}
	}
	return nil
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// writeCpio writes files as a newc cpio stream over the given codec.
// Hard link groups follow the GNU convention: only the last member of
// a group carries the data.
func writeCpio(out string, files []*InputFile, codec string, opt AddOptions, prog *Progress) error {
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	var w io.Writer = o
	var cw io.WriteCloser
	if codec != "" {
		cw, err = newCompressor(codec, o, opt.Level, opt.Threads, opt.Dict)
		if err != nil {
			return err
		}
		w = cw
	}

	type identity struct {
		ino   uint64
		nlink uint32
		uid   uint32
		gid   uint32
	}
	ids := make(map[*InputFile]identity, len(files))
	lastOfGroup := map[uint64]*InputFile{}
	for _, f := range files {
		if f.IsDir || f.Link != "" {
			continue
		}
		ino, nlink, uid, gid := fileIdentity(f.Path)
		ids[f] = identity{ino, nlink, uid, gid}
		if nlink > 1 && ino != 0 {
			lastOfGroup[ino] = f
		}
	}

	cw2 := cpiopkg.NewWriter(w)
	for _, f := range files {
		id := ids[f]
		hdr := &cpiopkg.Header{
			Name:    f.Name,
			Ino:     uint32(id.ino),
			Mode:    cpiopkg.UnixMode(fileInfoOf(f).Mode()),
			Uid:     id.uid,
			Gid:     id.gid,
			Nlink:   id.nlink,
			ModTime: f.ModTime,
		}
		if id.nlink == 0 {
			hdr.Nlink = 1
		}
		switch {
		case f.IsDir:
			hdr.Size = 0
			if err := cw2.WriteHeader(hdr); err != nil {
				return err
			}
		case f.Link != "":
			hdr.Size = int64(len(f.Link))
			if err := cw2.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := cw2.Write([]byte(f.Link)); err != nil {
				return err
			}
		default:
			carriesData := true
			if id.nlink > 1 && id.ino != 0 && lastOfGroup[id.ino] != f {
				carriesData = false
			}
			if carriesData {
				hdr.Size = f.Size
			}
			if err := cw2.WriteHeader(hdr); err != nil {
				return err
			}
			if carriesData {
				if err := copyFile(cw2, f, prog); err != nil {
					return err
				}
			}
		}
	}
	if err := cw2.Close(); err != nil {
		return err
	}
	if cw != nil {
		if err := cw.Close(); err != nil {
			return err
		}
	}
	return o.Close()
}
