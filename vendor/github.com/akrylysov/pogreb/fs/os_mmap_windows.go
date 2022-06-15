// +build windows

package fs

import (
	"os"
	"syscall"
	"unsafe"
)

func mmap(f *os.File, fileSize int64, mappingSize int64) ([]byte, error) {
	size := fileSize
	low, high := uint32(size), uint32(size>>32)
	fmap, err := syscall.CreateFileMapping(syscall.Handle(f.Fd()), nil, syscall.PAGE_READONLY, high, low, nil)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(fmap)
	ptr, err := syscall.MapViewOfFile(fmap, syscall.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		return nil, err
	}
	data := (*[maxMmapSize]byte)(unsafe.Pointer(ptr))[:size]
	return data, nil
}

func munmap(data []byte) error {
	return syscall.UnmapViewOfFile(uintptr(unsafe.Pointer(&data[0])))
}

func madviceRandom(data []byte) error {
	return nil
}

func (f *osMMapFile) Truncate(size int64) error {
	// Truncating a memory-mapped file fails on Windows. Unmap it first.
	if err := f.munmap(); err != nil {
		return err
	}
	if err := f.File.Truncate(size); err != nil {
		return err
	}
	f.size = size
	return f.mremap()
}
