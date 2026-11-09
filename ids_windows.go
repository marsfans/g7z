//go:build windows

package main

// fileIdentity is a stub on Windows: no inode/hard link metadata is
// collected, so cpio entries get nlink 1 and uid/gid 0.
func fileIdentity(path string) (ino uint64, nlink uint32, uid, gid uint32) {
	return 0, 1, 0, 0
}
