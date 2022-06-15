package fs

import (
	"io"
	"os"
)

const (
	initialMmapSize = 1024 << 20 // 1 GiB
)

type osMMapFS struct {
	osFS
}

// OSMMap is a file system backed by the os package and memory-mapped files.
var OSMMap FileSystem = &osMMapFS{}

func (fs *osMMapFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	if flag&os.O_APPEND != 0 {
		// osMMapFS doesn't support opening files in append-only mode.
		// The database doesn't currently use O_APPEND.
		return nil, errAppendModeNotSupported
	}
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	mf := &osMMapFile{
		File: f,
		size: stat.Size(),
	}
	if err := mf.mremap(); err != nil {
		return nil, err
	}
	return mf, nil
}

type osMMapFile struct {
	*os.File
	data     []byte
	offset   int64
	size     int64
	mmapSize int64
}

func (f *osMMapFile) WriteAt(p []byte, off int64) (int, error) {
	n, err := f.File.WriteAt(p, off)
	if err != nil {
		return 0, err
	}
	writeOff := off + int64(n)
	if writeOff > f.size {
		f.size = writeOff
	}
	return n, f.mremap()
}

func (f *osMMapFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	if err != nil {
		return 0, err
	}
	f.offset += int64(n)
	if f.offset > f.size {
		f.size = f.offset
	}
	return n, f.mremap()
}

func (f *osMMapFile) Seek(offset int64, whence int) (int64, error) {
	off, err := f.File.Seek(offset, whence)
	f.offset = off
	return off, err
}

func (f *osMMapFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	f.offset += int64(n)
	return n, err
}

func (f *osMMapFile) Slice(start int64, end int64) ([]byte, error) {
	if end > f.size {
		return nil, io.EOF
	}
	if f.data == nil {
		return nil, os.ErrClosed
	}
	return f.data[start:end], nil
}

func (f *osMMapFile) munmap() error {
	if f.data == nil {
		return nil
	}
	if err := munmap(f.data); err != nil {
		return err
	}
	f.data = nil
	f.mmapSize = 0
	return nil
}

func (f *osMMapFile) mmap(fileSize int64, mappingSize int64) error {
	if f.data != nil {
		if err := munmap(f.data); err != nil {
			return err
		}
	}

	data, err := mmap(f.File, fileSize, mappingSize)
	if err != nil {
		return err
	}

	_ = madviceRandom(data)

	f.data = data
	return nil
}

func (f *osMMapFile) mremap() error {
	mmapSize := f.mmapSize

	if mmapSize >= f.size {
		return nil
	}

	if mmapSize == 0 {
		mmapSize = initialMmapSize
		if mmapSize < f.size {
			mmapSize = f.size
		}
	} else {
		if err := f.munmap(); err != nil {
			return err
		}
		mmapSize *= 2
	}

	if err := f.mmap(f.size, mmapSize); err != nil {
		return err
	}

	// On Windows mmap may memory-map less than the requested size.
	f.mmapSize = int64(len(f.data))

	return nil
}

func (f *osMMapFile) Close() error {
	if err := f.munmap(); err != nil {
		return err
	}
	return f.File.Close()
}
