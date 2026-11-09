//go:build !windows

package main

import (
	"os"
	"syscall"
)

// fileIdentity returns the inode, hard link count and owner of path,
// used to reproduce hard link groups in cpio archives.
func fileIdentity(path string) (ino uint64, nlink uint32, uid, gid uint32) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 1, 0, 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino, uint32(st.Nlink), st.Uid, st.Gid
	}
	return 0, 1, 0, 0
}
