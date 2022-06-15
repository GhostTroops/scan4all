package fs

import (
	"os"
	"path/filepath"
)

// Sub returns a new file system rooted at dir.
func Sub(fsys FileSystem, dir string) FileSystem {
	return &subFS{
		fsys: fsys,
		root: dir,
	}
}

type subFS struct {
	fsys FileSystem
	root string
}

func (fs *subFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	subName := filepath.Join(fs.root, name)
	return fs.fsys.OpenFile(subName, flag, perm)
}

func (fs *subFS) Stat(name string) (os.FileInfo, error) {
	subName := filepath.Join(fs.root, name)
	return fs.fsys.Stat(subName)
}

func (fs *subFS) Remove(name string) error {
	subName := filepath.Join(fs.root, name)
	return fs.fsys.Remove(subName)
}

func (fs *subFS) Rename(oldpath, newpath string) error {
	subOldpath := filepath.Join(fs.root, oldpath)
	subNewpath := filepath.Join(fs.root, newpath)
	return fs.fsys.Rename(subOldpath, subNewpath)
}

func (fs *subFS) ReadDir(name string) ([]os.FileInfo, error) {
	subName := filepath.Join(fs.root, name)
	return fs.fsys.ReadDir(subName)
}

func (fs *subFS) CreateLockFile(name string, perm os.FileMode) (LockFile, bool, error) {
	subName := filepath.Join(fs.root, name)
	return fs.fsys.CreateLockFile(subName, perm)
}

var _ FileSystem = &subFS{}
