package pogreb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

type recordType int

const (
	recordTypePut recordType = iota
	recordTypeDelete

	segmentExt = ".psg"
)

// segment is a write-ahead log segment.
// It consists of a sequence of binary-encoded variable length records.
type segment struct {
	*file
	id         uint16 // Physical segment identifier.
	sequenceID uint64 // Logical monotonically increasing segment identifier.
	name       string
	meta       *segmentMeta
}

func segmentName(id uint16, sequenceID uint64) string {
	return fmt.Sprintf("%05d-%d%s", id, sequenceID, segmentExt)
}

type segmentMeta struct {
	Full          bool
	PutRecords    uint32
	DeleteRecords uint32
	DeletedKeys   uint32
	DeletedBytes  uint32
}

func segmentMetaName(id uint16, sequenceID uint64) string {
	return segmentName(id, sequenceID) + metaExt
}

// Binary representation of a segment record:
// +---------------+------------------+------------------+-...-+--...--+----------+
// | Key Size (2B) | Record Type (1b) | Value Size (31b) | Key | Value | CRC (4B) |
// +---------------+------------------+------------------+-...-+--...--+----------+
type record struct {
	rtype     recordType
	segmentID uint16
	offset    uint32
	data      []byte
	key       []byte
	value     []byte
}

func encodedRecordSize(kvSize uint32) uint32 {
	// key size, value size, key, value, crc32
	return 2 + 4 + kvSize + 4
}

func encodeRecord(key []byte, value []byte, rt recordType) []byte {
	size := encodedRecordSize(uint32(len(key) + len(value)))
	data := make([]byte, size)
	binary.LittleEndian.PutUint16(data[:2], uint16(len(key)))

	valLen := uint32(len(value))
	if rt == recordTypeDelete { // Set delete bit.
		valLen |= 1 << 31
	}
	binary.LittleEndian.PutUint32(data[2:], valLen)

	copy(data[6:], key)
	copy(data[6+len(key):], value)
	checksum := crc32.ChecksumIEEE(data[:6+len(key)+len(value)])
	binary.LittleEndian.PutUint32(data[size-4:size], checksum)
	return data
}

func encodePutRecord(key []byte, value []byte) []byte {
	return encodeRecord(key, value, recordTypePut)
}

func encodeDeleteRecord(key []byte) []byte {
	return encodeRecord(key, nil, recordTypeDelete)
}

// segmentIterator iterates over segment records.
type segmentIterator struct {
	f      *segment
	offset uint32
	r      *bufio.Reader
	buf    []byte // kv size and crc32 reusable buffer.
}

func newSegmentIterator(f *segment) (*segmentIterator, error) {
	if _, err := f.Seek(int64(headerSize), io.SeekStart); err != nil {
		return nil, err
	}
	return &segmentIterator{
		f:      f,
		offset: headerSize,
		r:      bufio.NewReader(f),
		buf:    make([]byte, 6),
	}, nil
}

func (it *segmentIterator) next() (record, error) {
	// Read key and value size.
	kvSizeBuf := it.buf
	if _, err := io.ReadFull(it.r, kvSizeBuf); err != nil {
		if err == io.EOF {
			return record{}, ErrIterationDone
		}
		return record{}, err
	}

	// Decode key size.
	keySize := uint32(binary.LittleEndian.Uint16(kvSizeBuf[:2]))

	// Decode value size and record type.
	rt := recordTypePut
	valueSize := binary.LittleEndian.Uint32(kvSizeBuf[2:])
	if valueSize&(1<<31) != 0 {
		rt = recordTypeDelete
		valueSize &^= 1 << 31
	}

	// Read key, value and checksum.
	recordSize := encodedRecordSize(keySize + valueSize)
	data := make([]byte, recordSize)
	copy(data, kvSizeBuf)
	if _, err := io.ReadFull(it.r, data[6:]); err != nil {
		return record{}, err
	}

	// Verify checksum.
	checksum := binary.LittleEndian.Uint32(data[len(data)-4:])
	if checksum != crc32.ChecksumIEEE(data[:len(data)-4]) {
		return record{}, errCorrupted
	}

	offset := it.offset
	it.offset += recordSize
	rec := record{
		rtype:     rt,
		segmentID: it.f.id,
		offset:    offset,
		data:      data,
		key:       data[6 : 6+keySize],
		value:     data[6+keySize : 6+keySize+valueSize],
	}
	return rec, nil
}
