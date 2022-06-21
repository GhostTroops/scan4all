package fs

import (
	"io/ioutil"
	"os"
)

type osFS struct{}

// OS is a file system backed by the os package.
var OS FileSystem = &osFS{}

func (fs *osFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &osFile{File: f}, nil
}

func (fs *osFS) CreateLockFile(name string, perm os.FileMode) (LockFile, bool, error) {
	return createLockFile(name, perm)
}

func (fs *osFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (fs *osFS) Remove(name string) error {
	return os.Remove(name)
}

func (fs *osFS) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (fs *osFS) ReadDir(name string) ([]os.FileInfo, error) {
	return ioutil.ReadDir(name)
}

type osFile struct {
	*os.File
}

func (f *osFile) Slice(start int64, end int64) ([]byte, error) {
	buf := make([]byte, end-start)
	_, err := f.ReadAt(buf, start)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

type osLockFile struct {
	*os.File
	path string
}

func (f *osLockFile) Unlock() error {
	if err := os.Remove(f.path); err != nil {
		return err
	}
	return f.Close()
}
