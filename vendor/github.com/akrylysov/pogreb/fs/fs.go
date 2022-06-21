/*
Package fs provides a file system interface.
*/
package fs

import (
	"errors"
	"io"
	"os"
)

var (
	errAppendModeNotSupported = errors.New("append mode is not supported")
)

// File is the interface compatible with os.File.
type File interface {
	io.Closer
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Writer
	io.WriterAt

	// Stat returns os.FileInfo describing the file.
	Stat() (os.FileInfo, error)

	// Sync commits the current contents of the file.
	Sync() error

	// Truncate changes the size of the file.
	Truncate(size int64) error

	// Slice reads and returns the contents of file from offset start to offset end.
	Slice(start int64, end int64) ([]byte, error)
}

// LockFile represents a lock file.
type LockFile interface {
	// Unlock and removes the lock file.
	Unlock() error
}

// FileSystem represents a file system.
type FileSystem interface {
	// OpenFile opens the file with specified flag.
	OpenFile(name string, flag int, perm os.FileMode) (File, error)

	// Stat returns os.FileInfo describing the file.
	Stat(name string) (os.FileInfo, error)

	// Remove removes the file.
	Remove(name string) error

	// Rename renames oldpath to newpath.
	Rename(oldpath, newpath string) error

	// ReadDir reads the directory and returns a list of directory entries.
	ReadDir(name string) ([]os.FileInfo, error)

	// CreateLockFile creates a lock file.
	CreateLockFile(name string, perm os.FileMode) (LockFile, bool, error)
}
