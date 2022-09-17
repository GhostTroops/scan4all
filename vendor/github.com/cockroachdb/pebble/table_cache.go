// Copyright 2020 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"bytes"
	"context"
	"fmt"
	"runtime/debug"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/invariants"
	"github.com/cockroachdb/pebble/internal/manifest"
	"github.com/cockroachdb/pebble/internal/private"
	"github.com/cockroachdb/pebble/sstable"
	"github.com/cockroachdb/pebble/vfs"
)

var emptyIter = &errorIter{err: nil}

var tableCacheLabels = pprof.Labels("pebble", "table-cache")

type tableCache struct {
	cache         *Cache
	shards        []*tableCacheShard
	filterMetrics FilterMetrics
}

func (c *tableCache) init(cacheID uint64, dirname string, fs vfs.FS, opts *Options, size int) {
	c.cache = opts.Cache
	c.cache.Ref()

	c.shards = make([]*tableCacheShard, opts.Experimental.TableCacheShards)
	for i := range c.shards {
		c.shards[i] = &tableCacheShard{}
		c.shards[i].init(cacheID, dirname, fs, opts, size/len(c.shards))
		c.shards[i].filterMetrics = &c.filterMetrics
	}
}

func (c *tableCache) getShard(fileNum FileNum) *tableCacheShard {
	return c.shards[uint64(fileNum)%uint64(len(c.shards))]
}

func (c *tableCache) newIters(
	file *manifest.FileMetadata, opts *IterOptions, bytesIterated *uint64,
) (internalIterator, internalIterator, error) {
	return c.getShard(file.FileNum).newIters(file, opts, bytesIterated)
}

func (c *tableCache) getTableProperties(file *fileMetadata) (*sstable.Properties, error) {
	return c.getShard(file.FileNum).getTableProperties(file)
}

func (c *tableCache) evict(fileNum FileNum) {
	c.getShard(fileNum).evict(fileNum)
}

func (c *tableCache) metrics() (CacheMetrics, FilterMetrics) {
	var m CacheMetrics
	for i := range c.shards {
		s := c.shards[i]
		s.mu.RLock()
		m.Count += int64(len(s.mu.nodes))
		s.mu.RUnlock()
		m.Hits += atomic.LoadInt64(&s.atomic.hits)
		m.Misses += atomic.LoadInt64(&s.atomic.misses)
	}
	m.Size = m.Count * int64(unsafe.Sizeof(sstable.Reader{}))
	f := FilterMetrics{
		Hits:   atomic.LoadInt64(&c.filterMetrics.Hits),
		Misses: atomic.LoadInt64(&c.filterMetrics.Misses),
	}
	return m, f
}

func (c *tableCache) withReader(meta *fileMetadata, fn func(*sstable.Reader) error) error {
	s := c.getShard(meta.FileNum)
	v := s.findNode(meta)
	defer s.unrefValue(v)
	if v.err != nil {
		base.MustExist(s.fs, v.filename, s.logger, v.err)
		return v.err
	}
	return fn(v.reader)
}

func (c *tableCache) iterCount() int64 {
	var n int64
	for i := range c.shards {
		n += int64(atomic.LoadInt32(&c.shards[i].atomic.iterCount))
	}
	return n
}

func (c *tableCache) Close() error {
	var err error
	for i := range c.shards {
		// The cache shard is not allocated yet, nothing to close
		if c.shards[i] == nil {
			continue
		}
		err = firstError(err, c.shards[i].Close())
	}
	c.cache.Unref()
	return err
}

type tableCacheShard struct {
	// WARNING: The following struct `atomic` contains fields are accessed atomically.
	//
	// Go allocations are guaranteed to be 64-bit aligned which we take advantage
	// of by placing the 64-bit fields which we access atomically at the beginning
	// of the DB struct. For more information, see https://golang.org/pkg/sync/atomic/#pkg-note-BUG.
	atomic struct {
		hits      int64
		misses    int64
		iterCount int32
	}

	logger  Logger
	cacheID uint64
	dirname string
	fs      vfs.FS
	opts    sstable.ReaderOptions
	size    int

	mu struct {
		sync.RWMutex
		nodes map[FileNum]*tableCacheNode
		// The iters map is only created and populated in race builds.
		iters map[sstable.Iterator][]byte

		handHot  *tableCacheNode
		handCold *tableCacheNode
		handTest *tableCacheNode

		coldTarget int
		sizeHot    int
		sizeCold   int
		sizeTest   int
	}
	releasing     sync.WaitGroup
	releasingCh   chan *tableCacheValue
	filterMetrics *FilterMetrics
}

func (c *tableCacheShard) init(cacheID uint64, dirname string, fs vfs.FS, opts *Options, size int) {
	c.logger = opts.Logger
	c.cacheID = cacheID
	c.dirname = dirname
	c.fs = fs
	c.opts = opts.MakeReaderOptions()
	c.size = size

	c.mu.nodes = make(map[FileNum]*tableCacheNode)
	c.mu.coldTarget = size
	c.releasingCh = make(chan *tableCacheValue, 100)
	go c.releaseLoop()

	if invariants.RaceEnabled {
		c.mu.iters = make(map[sstable.Iterator][]byte)
	}
}

func (c *tableCacheShard) releaseLoop() {
	pprof.Do(context.Background(), tableCacheLabels, func(context.Context) {
		for v := range c.releasingCh {
			v.release(c)
		}
	})
}

func (c *tableCacheShard) newIters(
	file *manifest.FileMetadata, opts *IterOptions, bytesIterated *uint64,
) (internalIterator, internalIterator, error) {
	// Calling findNode gives us the responsibility of decrementing v's
	// refCount. If opening the underlying table resulted in error, then we
	// decrement this straight away. Otherwise, we pass that responsibility to
	// the sstable iterator, which decrements when it is closed.
	v := c.findNode(file)
	if v.err != nil {
		defer c.unrefValue(v)
		base.MustExist(c.fs, v.filename, c.logger, v.err)
		return nil, nil, v.err
	}

	if opts != nil &&
		opts.TableFilter != nil &&
		!opts.TableFilter(v.reader.Properties.UserProperties) {
		// Return the empty iterator. This iterator has no mutable state, so
		// using a singleton is fine.
		c.unrefValue(v)
		return emptyIter, nil, nil
	}

	var iter sstable.Iterator
	var err error
	if bytesIterated != nil {
		iter, err = v.reader.NewCompactionIter(bytesIterated)
	} else {
		iter, err = v.reader.NewIter(opts.GetLowerBound(), opts.GetUpperBound())
	}
	if err != nil {
		c.unrefValue(v)
		return nil, nil, err
	}
	// NB: v.closeHook takes responsibility for calling unrefValue(v) here.
	iter.SetCloseHook(v.closeHook)

	atomic.AddInt32(&c.atomic.iterCount, 1)
	if invariants.RaceEnabled {
		c.mu.Lock()
		c.mu.iters[iter] = debug.Stack()
		c.mu.Unlock()
	}

	// NB: range-del iterator does not maintain a reference to the table, nor
	// does it need to read from it after creation.
	rangeDelIter, err := v.reader.NewRawRangeDelIter()
	if err != nil {
		_ = iter.Close()
		return nil, nil, err
	}
	if rangeDelIter != nil {
		return iter, rangeDelIter, nil
	}
	// NB: Translate a nil range-del iterator into a nil interface.
	return iter, nil, nil
}

// getTableProperties return sst table properties for target file
func (c *tableCacheShard) getTableProperties(file *fileMetadata) (*sstable.Properties, error) {
	// Calling findNode gives us the responsibility of decrementing v's refCount here
	v := c.findNode(file)
	defer c.unrefValue(v)

	if v.err != nil {
		return nil, v.err
	}
	return &v.reader.Properties, nil
}

// releaseNode releases a node from the tableCacheShard.
//
// c.mu must be held when calling this.
func (c *tableCacheShard) releaseNode(n *tableCacheNode) {
	c.unlinkNode(n)
	c.clearNode(n)
}

// unlinkNode removes a node from the tableCacheShard, leaving the shard
// reference in place.
//
// c.mu must be held when calling this.
func (c *tableCacheShard) unlinkNode(n *tableCacheNode) {
	delete(c.mu.nodes, n.meta.FileNum)

	switch n.ptype {
	case tableCacheNodeHot:
		c.mu.sizeHot--
	case tableCacheNodeCold:
		c.mu.sizeCold--
	case tableCacheNodeTest:
		c.mu.sizeTest--
	}

	if n == c.mu.handHot {
		c.mu.handHot = c.mu.handHot.prev()
	}
	if n == c.mu.handCold {
		c.mu.handCold = c.mu.handCold.prev()
	}
	if n == c.mu.handTest {
		c.mu.handTest = c.mu.handTest.prev()
	}

	if n.unlink() == n {
		// This was the last entry in the cache.
		c.mu.handHot = nil
		c.mu.handCold = nil
		c.mu.handTest = nil
	}

	n.links.prev = nil
	n.links.next = nil
}

func (c *tableCacheShard) clearNode(n *tableCacheNode) {
	if v := n.value; v != nil {
		n.value = nil
		c.unrefValue(v)
	}
}

// unrefValue decrements the reference count for the specified value, releasing
// it if the reference count fell to 0. Note that the value has a reference if
// it is present in tableCacheShard.mu.nodes, so a reference count of 0 means
// the node has already been removed from that map.
func (c *tableCacheShard) unrefValue(v *tableCacheValue) {
	if atomic.AddInt32(&v.refCount, -1) == 0 {
		c.releasing.Add(1)
		c.releasingCh <- v
	}
}

// findNode returns the node for the table with the given file number, creating
// that node if it didn't already exist. The caller is responsible for
// decrementing the returned node's refCount.
func (c *tableCacheShard) findNode(meta *fileMetadata) *tableCacheValue {
	// Fast-path for a hit in the cache. We grab the lock in shared mode, and use
	// a batching mechanism to perform updates to the LRU list.
	c.mu.RLock()
	if n := c.mu.nodes[meta.FileNum]; n != nil && n.value != nil {
		// Fast-path hit.
		//
		// The caller is responsible for decrementing the refCount.
		v := n.value
		atomic.AddInt32(&v.refCount, 1)
		c.mu.RUnlock()
		atomic.StoreInt32(&n.referenced, 1)
		atomic.AddInt64(&c.atomic.hits, 1)
		<-v.loaded
		return v
	}
	c.mu.RUnlock()

	c.mu.Lock()

	n := c.mu.nodes[meta.FileNum]
	switch {
	case n == nil:
		// Slow-path miss of a non-existent node.
		n = &tableCacheNode{
			meta:  meta,
			ptype: tableCacheNodeCold,
		}
		c.addNode(n)
		c.mu.sizeCold++

	case n.value != nil:
		// Slow-path hit of a hot or cold node.
		//
		// The caller is responsible for decrementing the refCount.
		v := n.value
		atomic.AddInt32(&v.refCount, 1)
		atomic.StoreInt32(&n.referenced, 1)
		atomic.AddInt64(&c.atomic.hits, 1)
		c.mu.Unlock()
		<-v.loaded
		return v

	default:
		// Slow-path miss of a test node.
		c.unlinkNode(n)
		c.mu.coldTarget++
		if c.mu.coldTarget > c.size {
			c.mu.coldTarget = c.size
		}

		atomic.StoreInt32(&n.referenced, 0)
		n.ptype = tableCacheNodeHot
		c.addNode(n)
		c.mu.sizeHot++
	}

	atomic.AddInt64(&c.atomic.misses, 1)

	v := &tableCacheValue{
		loaded:   make(chan struct{}),
		refCount: 2,
	}
	// Cache the closure invoked when an iterator is closed. This avoids an
	// allocation on every call to newIters.
	v.closeHook = func(i sstable.Iterator) error {
		if invariants.RaceEnabled {
			c.mu.Lock()
			delete(c.mu.iters, i)
			c.mu.Unlock()
		}
		c.unrefValue(v)
		atomic.AddInt32(&c.atomic.iterCount, -1)
		return nil
	}
	n.value = v

	c.mu.Unlock()

	// Note adding to the cache lists must complete before we begin loading the
	// table as a failure during load will result in the node being unlinked.
	pprof.Do(context.Background(), tableCacheLabels, func(context.Context) {
		v.load(meta, c)
	})
	return v
}

func (c *tableCacheShard) addNode(n *tableCacheNode) {
	c.evictNodes()
	c.mu.nodes[n.meta.FileNum] = n

	n.links.next = n
	n.links.prev = n
	if c.mu.handHot == nil {
		// First element.
		c.mu.handHot = n
		c.mu.handCold = n
		c.mu.handTest = n
	} else {
		c.mu.handHot.link(n)
	}

	if c.mu.handCold == c.mu.handHot {
		c.mu.handCold = c.mu.handCold.prev()
	}
}

func (c *tableCacheShard) evictNodes() {
	for c.size <= c.mu.sizeHot+c.mu.sizeCold && c.mu.handCold != nil {
		c.runHandCold()
	}
}

func (c *tableCacheShard) runHandCold() {
	n := c.mu.handCold
	if n.ptype == tableCacheNodeCold {
		if atomic.LoadInt32(&n.referenced) == 1 {
			atomic.StoreInt32(&n.referenced, 0)
			n.ptype = tableCacheNodeHot
			c.mu.sizeCold--
			c.mu.sizeHot++
		} else {
			c.clearNode(n)
			n.ptype = tableCacheNodeTest
			c.mu.sizeCold--
			c.mu.sizeTest++
			for c.size < c.mu.sizeTest && c.mu.handTest != nil {
				c.runHandTest()
			}
		}
	}

	c.mu.handCold = c.mu.handCold.next()

	for c.size-c.mu.coldTarget <= c.mu.sizeHot && c.mu.handHot != nil {
		c.runHandHot()
	}
}

func (c *tableCacheShard) runHandHot() {
	if c.mu.handHot == c.mu.handTest && c.mu.handTest != nil {
		c.runHandTest()
		if c.mu.handHot == nil {
			return
		}
	}

	n := c.mu.handHot
	if n.ptype == tableCacheNodeHot {
		if atomic.LoadInt32(&n.referenced) == 1 {
			atomic.StoreInt32(&n.referenced, 0)
		} else {
			n.ptype = tableCacheNodeCold
			c.mu.sizeHot--
			c.mu.sizeCold++
		}
	}

	c.mu.handHot = c.mu.handHot.next()
}

func (c *tableCacheShard) runHandTest() {
	if c.mu.sizeCold > 0 && c.mu.handTest == c.mu.handCold && c.mu.handCold != nil {
		c.runHandCold()
		if c.mu.handTest == nil {
			return
		}
	}

	n := c.mu.handTest
	if n.ptype == tableCacheNodeTest {
		c.mu.coldTarget--
		if c.mu.coldTarget < 0 {
			c.mu.coldTarget = 0
		}
		c.unlinkNode(n)
		c.clearNode(n)
	}

	c.mu.handTest = c.mu.handTest.next()
}

func (c *tableCacheShard) evict(fileNum FileNum) {
	c.mu.Lock()

	n := c.mu.nodes[fileNum]
	var v *tableCacheValue
	if n != nil {
		// NB: This is equivalent to tableCacheShard.releaseNode(), but we perform
		// the tableCacheNode.release() call synchronously below to ensure the
		// sstable file descriptor is closed before returning. Note that
		// tableCacheShard.releasing needs to be incremented while holding
		// tableCacheShard.mu in order to avoid a race with Close()
		c.unlinkNode(n)
		v = n.value
		if v != nil {
			if t := atomic.AddInt32(&v.refCount, -1); t != 0 {
				c.logger.Fatalf("sstable %s: refcount is not zero: %d\n%s", fileNum, t, debug.Stack())
			}
			c.releasing.Add(1)
		}
	}

	c.mu.Unlock()

	if v != nil {
		v.release(c)
	}

	c.opts.Cache.EvictFile(c.cacheID, fileNum)
}

func (c *tableCacheShard) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for leaked iterators. Note that we'll still perform cleanup below in
	// the case that there are leaked iterators.
	var err error
	if v := atomic.LoadInt32(&c.atomic.iterCount); v > 0 {
		if !invariants.RaceEnabled {
			err = errors.Errorf("leaked iterators: %d", errors.Safe(v))
		} else {
			var buf bytes.Buffer
			for _, stack := range c.mu.iters {
				fmt.Fprintf(&buf, "%s\n", stack)
			}
			err = errors.Errorf("leaked iterators: %d\n%s", errors.Safe(v), buf.String())
		}
	}

	for c.mu.handHot != nil {
		n := c.mu.handHot
		if n.value != nil {
			if atomic.AddInt32(&n.value.refCount, -1) == 0 {
				c.releasing.Add(1)
				c.releasingCh <- n.value
			}
		}
		c.unlinkNode(n)
	}
	c.mu.nodes = nil
	c.mu.handHot = nil
	c.mu.handCold = nil
	c.mu.handTest = nil

	// Only shutdown the releasing goroutine if there were no leaked
	// iterators. If there were leaked iterators, we leave the goroutine running
	// and the releasingCh open so that a subsequent iterator close can
	// complete. This behavior is used by iterator leak tests. Leaking the
	// goroutine for these tests is less bad not closing the iterator which
	// triggers other warnings about block cache handles not being released.
	if err == nil {
		close(c.releasingCh)
	}
	c.releasing.Wait()
	return err
}

type tableCacheValue struct {
	closeHook func(i sstable.Iterator) error
	reader    *sstable.Reader
	filename  string
	err       error
	loaded    chan struct{}
	// Reference count for the value. The reader is closed when the reference
	// count drops to zero.
	refCount int32
}

func (v *tableCacheValue) load(meta *fileMetadata, c *tableCacheShard) {
	// Try opening the fileTypeTable first.
	var f vfs.File
	v.filename = base.MakeFilename(c.fs, c.dirname, fileTypeTable, meta.FileNum)
	f, v.err = c.fs.Open(v.filename, vfs.RandomReadsOption)
	if v.err == nil {
		cacheOpts := private.SSTableCacheOpts(c.cacheID, meta.FileNum).(sstable.ReaderOption)
		reopenOpt := sstable.FileReopenOpt{FS: c.fs, Filename: v.filename}
		v.reader, v.err = sstable.NewReader(f, c.opts, cacheOpts, c.filterMetrics, reopenOpt)
	}
	if v.err == nil {
		if meta.SmallestSeqNum == meta.LargestSeqNum {
			v.reader.Properties.GlobalSeqNum = meta.LargestSeqNum
		}
	}
	if v.err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		// Lookup the node in the cache again as it might have already been
		// removed.
		n := c.mu.nodes[meta.FileNum]
		if n != nil && n.value == v {
			c.releaseNode(n)
		}
	}
	close(v.loaded)
}

func (v *tableCacheValue) release(c *tableCacheShard) {
	<-v.loaded
	// Nothing to be done about an error at this point. Close the reader if it is
	// open.
	if v.reader != nil {
		_ = v.reader.Close()
	}
	c.releasing.Done()
}

type tableCacheNodeType int8

const (
	tableCacheNodeTest tableCacheNodeType = iota
	tableCacheNodeCold
	tableCacheNodeHot
)

func (p tableCacheNodeType) String() string {
	switch p {
	case tableCacheNodeTest:
		return "test"
	case tableCacheNodeCold:
		return "cold"
	case tableCacheNodeHot:
		return "hot"
	}
	return "unknown"
}

type tableCacheNode struct {
	meta  *fileMetadata
	value *tableCacheValue

	links struct {
		next *tableCacheNode
		prev *tableCacheNode
	}
	ptype tableCacheNodeType
	// referenced is atomically set to indicate that this entry has been accessed
	// since the last time one of the clock hands swept it.
	referenced int32
}

func (n *tableCacheNode) next() *tableCacheNode {
	if n == nil {
		return nil
	}
	return n.links.next
}

func (n *tableCacheNode) prev() *tableCacheNode {
	if n == nil {
		return nil
	}
	return n.links.prev
}

func (n *tableCacheNode) link(s *tableCacheNode) {
	s.links.prev = n.links.prev
	s.links.prev.links.next = s
	s.links.next = n
	s.links.next.links.prev = s
}

func (n *tableCacheNode) unlink() *tableCacheNode {
	next := n.links.next
	n.links.prev.links.next = n.links.next
	n.links.next.links.prev = n.links.prev
	n.links.prev = n
	n.links.next = n
	return next
}
