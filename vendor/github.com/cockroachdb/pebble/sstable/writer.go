// Copyright 2011 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package sstable

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/cespare/xxhash/v2"
	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/cache"
	"github.com/cockroachdb/pebble/internal/crc"
	"github.com/cockroachdb/pebble/internal/private"
	"github.com/cockroachdb/pebble/internal/rangedel"
)

// WriterMetadata holds info about a finished sstable.
type WriterMetadata struct {
	Size           uint64
	SmallestPoint  InternalKey
	SmallestRange  InternalKey
	LargestPoint   InternalKey
	LargestRange   InternalKey
	SmallestSeqNum uint64
	LargestSeqNum  uint64
	Properties     Properties
}

func (m *WriterMetadata) updateSeqNum(seqNum uint64) {
	if m.SmallestSeqNum > seqNum {
		m.SmallestSeqNum = seqNum
	}
	if m.LargestSeqNum < seqNum {
		m.LargestSeqNum = seqNum
	}
}

// Smallest returns the smaller of SmallestPoint and SmallestRange.
func (m *WriterMetadata) Smallest(cmp Compare) InternalKey {
	if m.SmallestPoint.UserKey == nil {
		return m.SmallestRange
	}
	if m.SmallestRange.UserKey == nil {
		return m.SmallestPoint
	}
	if base.InternalCompare(cmp, m.SmallestPoint, m.SmallestRange) < 0 {
		return m.SmallestPoint
	}
	return m.SmallestRange
}

// Largest returns the larget of LargestPoint and LargestRange.
func (m *WriterMetadata) Largest(cmp Compare) InternalKey {
	if m.LargestPoint.UserKey == nil {
		return m.LargestRange
	}
	if m.LargestRange.UserKey == nil {
		return m.LargestPoint
	}
	if base.InternalCompare(cmp, m.LargestPoint, m.LargestRange) > 0 {
		return m.LargestPoint
	}
	return m.LargestRange
}

type flusher interface {
	Flush() error
}

type writeCloseSyncer interface {
	io.WriteCloser
	Sync() error
}

// Writer is a table writer.
type Writer struct {
	writer    io.Writer
	bufWriter *bufio.Writer
	syncer    writeCloseSyncer
	meta      WriterMetadata
	err       error
	// cacheID and fileNum are used to remove blocks written to the sstable from
	// the cache, providing a defense in depth against bugs which cause cache
	// collisions.
	cacheID uint64
	fileNum base.FileNum
	// The following fields are copied from Options.
	blockSize               int
	blockSizeThreshold      int
	indexBlockSize          int
	indexBlockSizeThreshold int
	compare                 Compare
	split                   Split
	formatKey               base.FormatKey
	compression             Compression
	separator               Separator
	successor               Successor
	tableFormat             TableFormat
	checksumType            ChecksumType
	cache                   *cache.Cache
	// disableKeyOrderChecks disables the checks that keys are added to an
	// sstable in order. It is intended for internal use only in the construction
	// of invalid sstables for testing. See tool/make_test_sstables.go.
	disableKeyOrderChecks bool
	// With two level indexes, the index/filter of a SST file is partitioned into
	// smaller blocks with an additional top-level index on them. When reading an
	// index/filter, only the top-level index is loaded into memory. The two level
	// index/filter then uses the top-level index to load on demand into the block
	// cache the partitions that are required to perform the index/filter query.
	//
	// Two level indexes are enabled automatically when there is more than one
	// index block.
	//
	// This is useful when there are very large index blocks, which generally occurs
	// with the usage of large keys. With large index blocks, the index blocks fight
	// the data blocks for block cache space and the index blocks are likely to be
	// re-read many times from the disk. The top level index, which has a much
	// smaller memory footprint, can be used to prevent the entire index block from
	// being loaded into the block cache.
	twoLevelIndex bool
	// Internal flag to allow creation of range-del-v1 format blocks. Only used
	// for testing. Note that v2 format blocks are backwards compatible with v1
	// format blocks.
	rangeDelV1Format bool
	block            blockWriter
	indexBlock       blockWriter
	rangeDelBlock    blockWriter
	props            Properties
	propCollectors   []TablePropertyCollector
	// compressedBuf is the destination buffer for compression. It is
	// re-used over the lifetime of the writer, avoiding the allocation of a
	// temporary buffer for each block.
	compressedBuf []byte
	// filter accumulates the filter block. If populated, the filter ingests
	// either the output of w.split (i.e. a prefix extractor) if w.split is not
	// nil, or the full keys otherwise.
	filter filterWriter
	// tmp is a scratch buffer, large enough to hold either footerLen bytes,
	// blockTrailerLen bytes, or (5 * binary.MaxVarintLen64) bytes.
	tmp [rocksDBFooterLen]byte

	xxHasher *xxhash.Digest

	topLevelIndexBlock blockWriter
	indexPartitions    []blockWriter
}

// Set sets the value for the given key. The sequence number is set to
// 0. Intended for use to externally construct an sstable before ingestion into
// a DB.
//
// TODO(peter): untested
func (w *Writer) Set(key, value []byte) error {
	if w.err != nil {
		return w.err
	}
	return w.addPoint(base.MakeInternalKey(key, 0, InternalKeyKindSet), value)
}

// Delete deletes the value for the given key. The sequence number is set to
// 0. Intended for use to externally construct an sstable before ingestion into
// a DB.
//
// TODO(peter): untested
func (w *Writer) Delete(key []byte) error {
	if w.err != nil {
		return w.err
	}
	return w.addPoint(base.MakeInternalKey(key, 0, InternalKeyKindDelete), nil)
}

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end). The sequence number is set to
// 0. Intended for use to externally construct an sstable before ingestion into
// a DB.
//
// TODO(peter): untested
func (w *Writer) DeleteRange(start, end []byte) error {
	if w.err != nil {
		return w.err
	}
	return w.addTombstone(base.MakeInternalKey(start, 0, InternalKeyKindRangeDelete), end)
}

// Merge adds an action to the DB that merges the value at key with the new
// value. The details of the merge are dependent upon the configured merge
// operator. The sequence number is set to 0. Intended for use to externally
// construct an sstable before ingestion into a DB.
//
// TODO(peter): untested
func (w *Writer) Merge(key, value []byte) error {
	if w.err != nil {
		return w.err
	}
	return w.addPoint(base.MakeInternalKey(key, 0, InternalKeyKindMerge), value)
}

// Add adds a key/value pair to the table being written. For a given Writer,
// the keys passed to Add must be in increasing order. The exception to this
// rule is range deletion tombstones. Range deletion tombstones need to be
// added ordered by their start key, but they can be added out of order from
// point entries. Additionally, range deletion tombstones must be fragmented
// (i.e. by rangedel.Fragmenter).
func (w *Writer) Add(key InternalKey, value []byte) error {
	if w.err != nil {
		return w.err
	}

	if key.Kind() == InternalKeyKindRangeDelete {
		return w.addTombstone(key, value)
	}
	return w.addPoint(key, value)
}

func (w *Writer) addPoint(key InternalKey, value []byte) error {
	if !w.disableKeyOrderChecks && w.meta.LargestPoint.UserKey != nil {
		// TODO(peter): Manually inlined version of base.InternalCompare(). This is
		// 3.5% faster on BenchmarkWriter on go1.13. Remove if go1.14 or future
		// versions show this to not be a performance win.
		x := w.compare(w.meta.LargestPoint.UserKey, key.UserKey)
		if x > 0 || (x == 0 && w.meta.LargestPoint.Trailer < key.Trailer) {
			w.err = errors.Errorf("pebble: keys must be added in order: %s, %s",
				w.meta.LargestPoint.Pretty(w.formatKey), key.Pretty(w.formatKey))
			return w.err
		}
	}

	if err := w.maybeFlush(key, value); err != nil {
		return err
	}

	for i := range w.propCollectors {
		if err := w.propCollectors[i].Add(key, value); err != nil {
			return err
		}
	}

	w.maybeAddToFilter(key.UserKey)
	w.block.add(key, value)

	w.meta.updateSeqNum(key.SeqNum())
	// block.curKey contains the most recently added key to the block.
	w.meta.LargestPoint.UserKey = w.block.curKey[:len(w.block.curKey)-8]
	w.meta.LargestPoint.Trailer = key.Trailer
	if w.meta.SmallestPoint.UserKey == nil {
		// NB: we clone w.meta.LargestPoint rather than "key", even though they are
		// semantically identical, because we need to ensure that SmallestPoint.UserKey
		// is not nil. This is required by WriterMetadata.Smallest in order to
		// distinguish between an unset SmallestPoint and a zero-length one.
		w.meta.SmallestPoint = w.meta.LargestPoint.Clone()
	}

	w.props.NumEntries++
	switch key.Kind() {
	case InternalKeyKindDelete:
		w.props.NumDeletions++
	case InternalKeyKindMerge:
		w.props.NumMergeOperands++
	}
	w.props.RawKeySize += uint64(key.Size())
	w.props.RawValueSize += uint64(len(value))
	return nil
}

func (w *Writer) addTombstone(key InternalKey, value []byte) error {
	if !w.disableKeyOrderChecks && !w.rangeDelV1Format && w.rangeDelBlock.nEntries > 0 {
		// Check that tombstones are being added in fragmented order. If the two
		// tombstones overlap, their start and end keys must be identical.
		prevKey := base.DecodeInternalKey(w.rangeDelBlock.curKey)
		switch c := w.compare(prevKey.UserKey, key.UserKey); {
		case c > 0:
			w.err = errors.Errorf("pebble: keys must be added in order: %s, %s",
				prevKey.Pretty(w.formatKey), key.Pretty(w.formatKey))
			return w.err
		case c == 0:
			prevValue := w.rangeDelBlock.curValue
			if w.compare(prevValue, value) != 0 {
				w.err = errors.Errorf("pebble: overlapping tombstones must be fragmented: %s vs %s",
					(rangedel.Tombstone{Start: prevKey, End: prevValue}).Pretty(w.formatKey),
					(rangedel.Tombstone{Start: key, End: value}).Pretty(w.formatKey))
				return w.err
			}
			if prevKey.SeqNum() <= key.SeqNum() {
				w.err = errors.Errorf("pebble: keys must be added in order: %s, %s",
					prevKey.Pretty(w.formatKey), key.Pretty(w.formatKey))
				return w.err
			}
		default:
			prevValue := w.rangeDelBlock.curValue
			if w.compare(prevValue, key.UserKey) > 0 {
				w.err = errors.Errorf("pebble: overlapping tombstones must be fragmented: %s vs %s",
					(rangedel.Tombstone{Start: prevKey, End: prevValue}).Pretty(w.formatKey),
					(rangedel.Tombstone{Start: key, End: value}).Pretty(w.formatKey))
				return w.err
			}
		}
	}

	if key.Trailer == InternalKeyRangeDeleteSentinel {
		w.err = errors.Errorf("pebble: cannot add range delete sentinel: %s", key.Pretty(w.formatKey))
		return w.err
	}

	for i := range w.propCollectors {
		if err := w.propCollectors[i].Add(key, value); err != nil {
			return err
		}
	}

	w.meta.updateSeqNum(key.SeqNum())

	switch {
	case w.rangeDelV1Format:
		// Range tombstones are not fragmented in the v1 (i.e. RocksDB) range
		// deletion block format, so we need to track the largest range tombstone
		// end key as every range tombstone is added.
		//
		// Note that writing the v1 format is only supported for tests.
		if w.props.NumRangeDeletions == 0 {
			w.meta.SmallestRange = key.Clone()
			w.meta.LargestRange = base.MakeRangeDeleteSentinelKey(value).Clone()
		} else {
			if base.InternalCompare(w.compare, w.meta.SmallestRange, key) > 0 {
				w.meta.SmallestRange = key.Clone()
			}
			end := base.MakeRangeDeleteSentinelKey(value)
			if base.InternalCompare(w.compare, w.meta.LargestRange, end) < 0 {
				w.meta.LargestRange = end.Clone()
			}
		}

	default:
		// Range tombstones are fragmented in the v2 range deletion block format,
		// so the start key of the first range tombstone added will be the smallest
		// range tombstone key. The largest range tombstone key will be determined
		// in Writer.Close() as the end key of the last range tombstone added.
		if w.props.NumRangeDeletions == 0 {
			w.meta.SmallestRange = key.Clone()
		}
	}

	w.props.NumEntries++
	w.props.NumDeletions++
	w.props.NumRangeDeletions++
	w.props.RawKeySize += uint64(key.Size())
	w.props.RawValueSize += uint64(len(value))
	w.rangeDelBlock.add(key, value)
	return nil
}

func (w *Writer) maybeAddToFilter(key []byte) {
	if w.filter != nil {
		if w.split != nil {
			prefix := key[:w.split(key)]
			w.filter.addKey(prefix)
		} else {
			w.filter.addKey(key)
		}
	}
}

func (w *Writer) maybeFlush(key InternalKey, value []byte) error {
	if !shouldFlush(key, value, &w.block, w.blockSize, w.blockSizeThreshold) {
		return nil
	}

	bh, err := w.writeBlock(w.block.finish(), w.compression)
	if err != nil {
		w.err = err
		return w.err
	}
	w.addIndexEntry(key, bh)
	return nil
}

// addIndexEntry adds an index entry for the specified key and block handle.
func (w *Writer) addIndexEntry(key InternalKey, bh BlockHandle) {
	if bh.Length == 0 {
		// A valid blockHandle must be non-zero.
		// In particular, it must have a non-zero length.
		return
	}
	prevKey := base.DecodeInternalKey(w.block.curKey)
	var sep InternalKey
	if key.UserKey == nil && key.Trailer == 0 {
		sep = prevKey.Successor(w.compare, w.successor, nil)
	} else {
		sep = prevKey.Separator(w.compare, w.separator, nil, key)
	}
	n := encodeBlockHandle(w.tmp[:], bh)

	if supportsTwoLevelIndex(w.tableFormat) &&
		shouldFlush(sep, w.tmp[:n], &w.indexBlock, w.indexBlockSize, w.indexBlockSizeThreshold) {
		// Enable two level indexes if there is more than one index block.
		w.twoLevelIndex = true
		w.finishIndexBlock()
	}

	w.indexBlock.add(sep, w.tmp[:n])
}

func shouldFlush(
	key InternalKey, value []byte, block *blockWriter, blockSize, sizeThreshold int,
) bool {
	if block.nEntries == 0 {
		return false
	}

	size := block.estimatedSize()
	if size >= blockSize {
		return true
	}

	// The block is currently smaller than the target size.
	if size <= sizeThreshold {
		// The block is smaller than the threshold size at which we'll consider
		// flushing it.
		return false
	}

	newSize := size + key.Size() + len(value)
	if block.nEntries%block.restartInterval == 0 {
		newSize += 4
	}
	newSize += 4                              // varint for shared prefix length
	newSize += uvarintLen(uint32(key.Size())) // varint for unshared key bytes
	newSize += uvarintLen(uint32(len(value))) // varint for value size
	// Flush if the block plus the new entry is larger than the target size.
	return newSize > blockSize
}

// finishIndexBlock finishes the current index block and adds it to the top
// level index block. This is only used when two level indexes are enabled.
func (w *Writer) finishIndexBlock() {
	w.indexPartitions = append(w.indexPartitions, w.indexBlock)
	w.indexBlock = blockWriter{
		restartInterval: 1,
	}
}

func (w *Writer) writeTwoLevelIndex() (BlockHandle, error) {
	// Add the final unfinished index.
	w.finishIndexBlock()

	for i := range w.indexPartitions {
		b := &w.indexPartitions[i]
		w.props.NumDataBlocks += uint64(b.nEntries)
		sep := base.DecodeInternalKey(b.curKey)
		data := b.finish()
		w.props.IndexSize += uint64(len(data))
		bh, err := w.writeBlock(data, w.compression)
		if err != nil {
			return BlockHandle{}, err
		}
		n := encodeBlockHandle(w.tmp[:], bh)
		w.topLevelIndexBlock.add(sep, w.tmp[:n])
	}

	// NB: RocksDB includes the block trailer length in the index size
	// property, though it doesn't include the trailer in the top level
	// index size property.
	w.props.IndexPartitions = uint64(len(w.indexPartitions))
	w.props.TopLevelIndexSize = uint64(w.topLevelIndexBlock.estimatedSize())
	w.props.IndexSize += w.props.TopLevelIndexSize + blockTrailerLen

	return w.writeBlock(w.topLevelIndexBlock.finish(), w.compression)
}

func (w *Writer) writeBlock(b []byte, compression Compression) (BlockHandle, error) {
	// Compress the buffer, discarding the result if the improvement isn't at
	// least 12.5%.
	blockType, compressed := compressBlock(compression, b, w.compressedBuf)
	if blockType != noCompressionBlockType && cap(compressed) > cap(w.compressedBuf) {
		w.compressedBuf = compressed[:cap(compressed)]
	}
	if len(compressed) < len(b)-len(b)/8 {
		b = compressed
	} else {
		blockType = noCompressionBlockType
	}

	w.tmp[0] = blockType

	// Calculate the checksum.
	var checksum uint32
	switch w.checksumType {
	case ChecksumTypeCRC32c:
		checksum = crc.New(b).Update(w.tmp[:1]).Value()
	case ChecksumTypeXXHash64:
		if w.xxHasher == nil {
			w.xxHasher = xxhash.New()
		} else {
			w.xxHasher.Reset()
		}
		w.xxHasher.Write(b)
		w.xxHasher.Write(w.tmp[:1])
		checksum = uint32(w.xxHasher.Sum64())
	default:
		return BlockHandle{}, errors.Newf("unsupported checksum type: %d", w.checksumType)
	}
	binary.LittleEndian.PutUint32(w.tmp[1:5], checksum)
	bh := BlockHandle{w.meta.Size, uint64(len(b))}

	if w.cacheID != 0 && w.fileNum != 0 {
		// Remove the block being written from the cache. This provides defense in
		// depth against bugs which cause cache collisions.
		//
		// TODO(peter): Alternatively, we could add the uncompressed value to the
		// cache.
		w.cache.Delete(w.cacheID, w.fileNum, bh.Offset)
	}

	// Write the bytes to the file.
	n, err := w.writer.Write(b)
	if err != nil {
		return BlockHandle{}, err
	}
	w.meta.Size += uint64(n)
	n, err = w.writer.Write(w.tmp[:blockTrailerLen])
	if err != nil {
		return BlockHandle{}, err
	}
	w.meta.Size += uint64(n)

	return bh, nil
}

// Close finishes writing the table and closes the underlying file that the
// table was written to.
func (w *Writer) Close() (err error) {
	defer func() {
		if w.syncer == nil {
			return
		}
		err1 := w.syncer.Close()
		if err == nil {
			err = err1
		}
		w.syncer = nil
	}()
	if w.err != nil {
		return w.err
	}

	// Finish the last data block, or force an empty data block if there
	// aren't any data blocks at all.
	if w.block.nEntries > 0 || w.indexBlock.nEntries == 0 {
		bh, err := w.writeBlock(w.block.finish(), w.compression)
		if err != nil {
			w.err = err
			return w.err
		}
		w.addIndexEntry(InternalKey{}, bh)
	}
	w.props.DataSize = w.meta.Size

	// Write the filter block.
	var metaindex rawBlockWriter
	metaindex.restartInterval = 1
	if w.filter != nil {
		b, err := w.filter.finish()
		if err != nil {
			w.err = err
			return w.err
		}
		bh, err := w.writeBlock(b, NoCompression)
		if err != nil {
			w.err = err
			return w.err
		}
		n := encodeBlockHandle(w.tmp[:], bh)
		metaindex.add(InternalKey{UserKey: []byte(w.filter.metaName())}, w.tmp[:n])
		w.props.FilterPolicyName = w.filter.policyName()
		w.props.FilterSize = bh.Length
	}

	var indexBH BlockHandle
	if w.twoLevelIndex {
		w.props.IndexType = twoLevelIndex
		// Write the two level index block.
		indexBH, err = w.writeTwoLevelIndex()
		if err != nil {
			w.err = err
			return w.err
		}
	} else {
		w.props.IndexType = binarySearchIndex
		// NB: RocksDB includes the block trailer length in the index size
		// property, though it doesn't include the trailer in the filter size
		// property.
		w.props.IndexSize = uint64(w.indexBlock.estimatedSize()) + blockTrailerLen
		w.props.NumDataBlocks = uint64(w.indexBlock.nEntries)

		// Write the single level index block.
		indexBH, err = w.writeBlock(w.indexBlock.finish(), w.compression)
		if err != nil {
			w.err = err
			return w.err
		}
	}

	// Write the range-del block. The block handle must added to the meta index block
	// after the properties block has been written. This is because the entries in the
	// metaindex block must be sorted by key.
	var rangeDelBH BlockHandle
	if w.props.NumRangeDeletions > 0 {
		if !w.rangeDelV1Format {
			// Because the range tombstones are fragmented in the v2 format, the end
			// key of the last added range tombstone will be the largest range
			// tombstone key. Note that we need to make this into a range deletion
			// sentinel because sstable boundaries are inclusive while the end key of
			// a range deletion tombstone is exclusive. A Clone() is necessary as
			// rangeDelBlock.curValue is the same slice that will get passed
			// into w.writer, and some implementations of vfs.File mutate the
			// slice passed into Write(). Also, w.meta will often outlive the
			// blockWriter, and so cloning curValue allows the rangeDelBlock's
			// internal buffer to get gc'd.
			w.meta.LargestRange = base.MakeRangeDeleteSentinelKey(w.rangeDelBlock.curValue).Clone()
		}
		rangeDelBH, err = w.writeBlock(w.rangeDelBlock.finish(), NoCompression)
		if err != nil {
			w.err = err
			return w.err
		}
	}

	{
		userProps := make(map[string]string)
		for i := range w.propCollectors {
			if err := w.propCollectors[i].Finish(userProps); err != nil {
				return err
			}
		}
		if len(userProps) > 0 {
			w.props.UserProperties = userProps
		}

		// Write the properties block.
		var raw rawBlockWriter
		// The restart interval is set to infinity because the properties block
		// is always read sequentially and cached in a heap located object. This
		// reduces table size without a significant impact on performance.
		raw.restartInterval = propertiesBlockRestartInterval
		w.props.CompressionOptions = rocksDBCompressionOptions
		w.props.save(&raw)
		bh, err := w.writeBlock(raw.finish(), NoCompression)
		if err != nil {
			w.err = err
			return w.err
		}
		n := encodeBlockHandle(w.tmp[:], bh)
		metaindex.add(InternalKey{UserKey: []byte(metaPropertiesName)}, w.tmp[:n])
	}

	// Add the range deletion block handle to the metaindex block.
	if w.props.NumRangeDeletions > 0 {
		n := encodeBlockHandle(w.tmp[:], rangeDelBH)
		// The v2 range-del block encoding is backwards compatible with the v1
		// encoding. We add meta-index entries for both the old name and the new
		// name so that old code can continue to find the range-del block and new
		// code knows that the range tombstones in the block are fragmented and
		// sorted.
		metaindex.add(InternalKey{UserKey: []byte(metaRangeDelName)}, w.tmp[:n])
		if !w.rangeDelV1Format {
			metaindex.add(InternalKey{UserKey: []byte(metaRangeDelV2Name)}, w.tmp[:n])
		}
	}

	// Write the metaindex block. It might be an empty block, if the filter
	// policy is nil. NoCompression is specified because a) RocksDB never
	// compresses the meta-index block and b) RocksDB has some code paths which
	// expect the meta-index block to not be compressed.
	metaindexBH, err := w.writeBlock(metaindex.blockWriter.finish(), NoCompression)
	if err != nil {
		w.err = err
		return w.err
	}

	// Write the table footer.
	footer := footer{
		format:      w.tableFormat,
		checksum:    w.checksumType,
		metaindexBH: metaindexBH,
		indexBH:     indexBH,
	}
	var n int
	if n, err = w.writer.Write(footer.encode(w.tmp[:])); err != nil {
		w.err = err
		return w.err
	}
	w.meta.Size += uint64(n)
	w.meta.Properties = w.props

	// Flush the buffer.
	if w.bufWriter != nil {
		if err := w.bufWriter.Flush(); err != nil {
			w.err = err
			return err
		}
	}

	if err := w.syncer.Sync(); err != nil {
		w.err = err
		return err
	}

	// Make any future calls to Set or Close return an error.
	w.err = errors.New("pebble: writer is closed")
	return nil
}

// EstimatedSize returns the estimated size of the sstable being written if a
// called to Finish() was made without adding additional keys.
func (w *Writer) EstimatedSize() uint64 {
	return w.meta.Size + uint64(w.block.estimatedSize()+w.indexBlock.estimatedSize())
}

// Metadata returns the metadata for the finished sstable. Only valid to call
// after the sstable has been finished.
func (w *Writer) Metadata() (*WriterMetadata, error) {
	if w.syncer != nil {
		return nil, errors.New("pebble: writer is not closed")
	}
	return &w.meta, nil
}

// WriterOption provide an interface to do work on Writer while it is being
// opened.
type WriterOption interface {
	// writerAPply is called on the writer during opening in order to set
	// internal parameters.
	writerApply(*Writer)
}

// internalTableOpt is a WriterOption that sets properties for sstables being
// created by the db itself (i.e. through flushes and compactions), as opposed
// to those meant for ingestion.
type internalTableOpt struct{}

func (i internalTableOpt) writerApply(w *Writer) {
	// Set the external sst version to 0. This is what RocksDB expects for
	// db-internal sstables; otherwise, it could apply a global sequence number.
	w.props.ExternalFormatVersion = 0
}

// NewWriter returns a new table writer for the file. Closing the writer will
// close the file.
func NewWriter(f writeCloseSyncer, o WriterOptions, extraOpts ...WriterOption) *Writer {
	o = o.ensureDefaults()
	w := &Writer{
		syncer: f,
		meta: WriterMetadata{
			SmallestSeqNum: math.MaxUint64,
		},
		blockSize:               o.BlockSize,
		blockSizeThreshold:      (o.BlockSize*o.BlockSizeThreshold + 99) / 100,
		indexBlockSize:          o.IndexBlockSize,
		indexBlockSizeThreshold: (o.IndexBlockSize*o.BlockSizeThreshold + 99) / 100,
		compare:                 o.Comparer.Compare,
		split:                   o.Comparer.Split,
		formatKey:               o.Comparer.FormatKey,
		compression:             o.Compression,
		separator:               o.Comparer.Separator,
		successor:               o.Comparer.Successor,
		tableFormat:             o.TableFormat,
		checksumType:            o.Checksum,
		cache:                   o.Cache,
		block: blockWriter{
			restartInterval: o.BlockRestartInterval,
		},
		indexBlock: blockWriter{
			restartInterval: 1,
		},
		rangeDelBlock: blockWriter{
			restartInterval: 1,
		},
		topLevelIndexBlock: blockWriter{
			restartInterval: 1,
		},
	}
	if f == nil {
		w.err = errors.New("pebble: nil file")
		return w
	}

	// Note that WriterOptions are applied in two places; the ones with a
	// preApply() method are applied here, and the rest are applied after
	// default properties are set.
	type preApply interface{ preApply() }
	for _, opt := range extraOpts {
		if _, ok := opt.(preApply); ok {
			opt.writerApply(w)
		}
	}

	w.props.PrefixExtractorName = "nullptr"
	if o.FilterPolicy != nil {
		switch o.FilterType {
		case TableFilter:
			w.filter = newTableFilterWriter(o.FilterPolicy)
			if w.split != nil {
				w.props.PrefixExtractorName = o.Comparer.Name
				w.props.PrefixFiltering = true
			} else {
				w.props.WholeKeyFiltering = true
			}
		default:
			panic(fmt.Sprintf("unknown filter type: %v", o.FilterType))
		}
	}

	w.props.ColumnFamilyID = math.MaxInt32
	w.props.ComparerName = o.Comparer.Name
	w.props.CompressionName = o.Compression.String()
	w.props.MergerName = o.MergerName
	w.props.PropertyCollectorNames = "[]"
	w.props.ExternalFormatVersion = rocksDBExternalFormatVersion

	if len(o.TablePropertyCollectors) > 0 {
		w.propCollectors = make([]TablePropertyCollector, len(o.TablePropertyCollectors))
		var buf bytes.Buffer
		buf.WriteString("[")
		for i := range o.TablePropertyCollectors {
			w.propCollectors[i] = o.TablePropertyCollectors[i]()
			if i > 0 {
				buf.WriteString(",")
			}
			buf.WriteString(w.propCollectors[i].Name())
		}
		buf.WriteString("]")
		w.props.PropertyCollectorNames = buf.String()
	}

	// Apply the remaining WriterOptions that do not have a preApply() method.
	for _, opt := range extraOpts {
		if _, ok := opt.(preApply); !ok {
			opt.writerApply(w)
		}
	}

	// If f does not have a Flush method, do our own buffering.
	if _, ok := f.(flusher); ok {
		w.writer = f
	} else {
		w.bufWriter = bufio.NewWriter(f)
		w.writer = w.bufWriter
	}
	return w
}

func init() {
	private.SSTableWriterDisableKeyOrderChecks = func(i interface{}) {
		w := i.(*Writer)
		w.disableKeyOrderChecks = true
	}
	private.SSTableInternalTableOpt = internalTableOpt{}
}
