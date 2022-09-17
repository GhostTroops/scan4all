// Copyright 2021 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package sstable

import (
	"encoding/binary"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/cache"
	"github.com/golang/snappy"
)

// decompressBlock decompresses an SST block, with space allocated from a cache.
func decompressBlock(cache *cache.Cache, blockType byte, b []byte) (*cache.Value, error) {
	// first obtain the decoded length.
	var (
		decodedLen int
		err        error
	)
	switch blockType {
	case noCompressionBlockType:
		return nil, nil
	case snappyCompressionBlockType:
		decodedLen, err = snappy.DecodedLen(b)
	case zstdCompressionBlockType:
		// This will also be used by zlib, bzip2 and lz4 to retrieve the decodedLen
		// if we implement these algorithms in the future.
		decodedLenU64, varIntLen := binary.Uvarint(b)
		if varIntLen <= 0 {
			return nil, base.CorruptionErrorf("pebble/table: compression block has invalid length")
		}
		decodedLen = int(decodedLenU64)
		b = b[varIntLen:]
	default:
		return nil, base.CorruptionErrorf("pebble/table: unknown block compression: %d", errors.Safe(blockType))
	}

	// Allocate sufficient space from the cache.
	decoded := cache.Alloc(decodedLen)
	decodedBuf := decoded.Buf()
	defer func() {
		if decoded != nil {
			cache.Free(decoded)
		}
	}()

	// Perform decompression.
	// NB: the value of `b` for snappy is different than the other cases since it includes the
	// length varint at the front, while for the others it has already been stripped off.
	// The implementation of snappy.Decode handles this correctly.
	var result []byte
	switch blockType {
	case snappyCompressionBlockType:
		result, err = snappy.Decode(decodedBuf, b)
	case zstdCompressionBlockType:
		result, err = decodeZstd(decodedBuf, b)
	}
	if err != nil {
		return nil, base.MarkCorruptionError(err)
	}
	if len(result) != 0 && (len(result) != len(decodedBuf) || &result[0] != &decodedBuf[0]) {
		return nil, base.CorruptionErrorf("pebble/table: decompressed into unexpected buffer: %p != %p",
			errors.Safe(result), errors.Safe(decodedBuf))
	}

	v := decoded
	decoded = nil
	return v, nil
}

// compressBlock compresses an SST block, using compressBuf as the desired destination.
func compressBlock(compression Compression, b []byte, compressedBuf []byte) (blockType byte, compressed []byte) {
	switch compression {
	case SnappyCompression:
		return snappyCompressionBlockType, snappy.Encode(compressedBuf, b)
	case NoCompression:
		return noCompressionBlockType, b
	}

	if len(compressedBuf) < binary.MaxVarintLen64 {
		compressedBuf = append(compressedBuf, make([]byte, binary.MaxVarintLen64-len(compressedBuf))...)
	}
	varIntLen := binary.PutUvarint(compressedBuf, uint64(len(b)))
	switch compression {
	case ZstdCompression:
		return zstdCompressionBlockType, encodeZstd(compressedBuf, varIntLen, b)
	default:
		return noCompressionBlockType, b
	}
}
