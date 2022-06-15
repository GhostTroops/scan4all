package fs

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

type memFS struct {
	files map[string]*memFile
}

// Mem is a file system backed by memory.
var Mem FileSystem = &memFS{files: map[string]*memFile{}}

func (fs *memFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	if flag&os.O_APPEND != 0 {
		// memFS doesn't support opening files in append-only mode.
		// The database doesn't currently use O_APPEND.
		return nil, errAppendModeNotSupported
	}
	f := fs.files[name]
	if f == nil || (flag&os.O_TRUNC) != 0 {
		f = &memFile{
			name: name,
			perm: perm, // Perm is saved to return it in Mode, but don't do anything else with it yet.
		}
		fs.files[name] = f
	} else if !f.closed {
		return nil, os.ErrExist
	} else {
		f.offset = 0
		f.closed = false
	}
	return f, nil
}

func (fs *memFS) CreateLockFile(name string, perm os.FileMode) (LockFile, bool, error) {
	_, exists := fs.files[name]
	_, err := fs.OpenFile(name, 0, perm)
	if err != nil {
		return nil, false, err
	}
	return fs.files[name], exists, nil
}

func (fs *memFS) Stat(name string) (os.FileInfo, error) {
	if f, ok := fs.files[name]; ok {
		return f, nil
	}
	return nil, os.ErrNotExist
}

func (fs *memFS) Remove(name string) error {
	if _, ok := fs.files[name]; ok {
		delete(fs.files, name)
		return nil
	}
	return os.ErrNotExist
}

func (fs *memFS) Rename(oldpath, newpath string) error {
	if f, ok := fs.files[oldpath]; ok {
		delete(fs.files, oldpath)
		fs.files[newpath] = f
		f.name = newpath
		return nil
	}
	return os.ErrNotExist
}

func (fs *memFS) ReadDir(dir string) ([]os.FileInfo, error) {
	dir = filepath.Clean(dir)
	var fis []os.FileInfo
	for name, f := range fs.files {
		if filepath.Dir(name) == dir {
			fis = append(fis, f)
		}
	}
	return fis, nil
}

type memFile struct {
	name   string
	perm   os.FileMode
	buf    []byte
	size   int64
	offset int64
	closed bool
}

func (f *memFile) Close() error {
	if f.closed {
		return os.ErrClosed
	}
	f.closed = true
	return nil
}

func (f *memFile) Unlock() error {
	if err := f.Close(); err != nil {
		return err
	}
	return Mem.Remove(f.name)
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	if f.closed {
		return 0, os.ErrClosed
	}
	if off >= f.size {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > f.size-off {
		copy(p, f.buf[off:])
		return int(f.size - off), nil
	}
	copy(p, f.buf[off:off+n])
	return int(n), nil
}

func (f *memFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.offset)
	if err != nil {
		return n, err
	}
	f.offset += int64(n)
	return n, err
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	if f.closed {
		return 0, os.ErrClosed
	}
	n := int64(len(p))
	if off+n > f.size {
		f.truncate(off + n)
	}
	copy(f.buf[off:off+n], p)
	return int(n), nil
}

func (f *memFile) Write(p []byte) (int, error) {
	n, err := f.WriteAt(p, f.offset)
	if err != nil {
		return n, err
	}
	f.offset += int64(n)
	return n, err
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	if f.closed {
		return 0, os.ErrClosed
	}
	switch whence {
	case io.SeekEnd:
		f.offset = f.size + offset
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	}
	return f.offset, nil
}

func (f *memFile) Stat() (os.FileInfo, error) {
	if f.closed {
		return f, os.ErrClosed
	}
	return f, nil
}

func (f *memFile) Sync() error {
	if f.closed {
		return os.ErrClosed
	}
	return nil
}

func (f *memFile) truncate(size int64) {
	if size > f.size {
		diff := int(size - f.size)
		f.buf = append(f.buf, make([]byte, diff)...)
	} else {
		f.buf = f.buf[:size]
	}
	f.size = size
}

func (f *memFile) Truncate(size int64) error {
	if f.closed {
		return os.ErrClosed
	}
	f.truncate(size)
	return nil
}

func (f *memFile) Name() string {
	_, name := filepath.Split(f.name)
	return name
}

func (f *memFile) Size() int64 {
	return f.size
}

func (f *memFile) Mode() os.FileMode {
	return f.perm
}

func (f *memFile) ModTime() time.Time {
	return time.Now()
}

func (f *memFile) IsDir() bool {
	return false
}

func (f *memFile) Sys() interface{} {
	return nil
}

func (f *memFile) Slice(start int64, end int64) ([]byte, error) {
	if f.closed {
		return nil, os.ErrClosed
	}
	if end > f.size {
		return nil, io.EOF
	}
	return f.buf[start:end], nil
}
