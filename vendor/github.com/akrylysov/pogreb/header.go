package pogreb

import (
	"bytes"
	"encoding/binary"
)

const (
	formatVersion = 2 // File format version.
	headerSize    = 512
)

var (
	signature = [8]byte{'p', 'o', 'g', 'r', 'e', 'b', '\x0e', '\xfd'}
)

type header struct {
	signature     [8]byte
	formatVersion uint32
}

func newHeader() *header {
	return &header{
		signature:     signature,
		formatVersion: formatVersion,
	}
}

func (h header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, headerSize)
	copy(buf[:8], h.signature[:])
	binary.LittleEndian.PutUint32(buf[8:12], h.formatVersion)
	return buf, nil
}

func (h *header) UnmarshalBinary(data []byte) error {
	if !bytes.Equal(data[:8], signature[:]) {
		return errCorrupted
	}
	copy(h.signature[:], data[:8])
	h.formatVersion = binary.LittleEndian.Uint32(data[8:12])
	return nil
}
