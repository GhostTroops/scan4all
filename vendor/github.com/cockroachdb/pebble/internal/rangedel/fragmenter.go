// Copyright 2018 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package rangedel

import (
	"fmt"
	"sort"

	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/internal/invariants"
)

type tombstonesByStartKey struct {
	cmp base.Compare
	buf []Tombstone
}

func (v *tombstonesByStartKey) Len() int { return len(v.buf) }
func (v *tombstonesByStartKey) Less(i, j int) bool {
	return base.InternalCompare(v.cmp, v.buf[i].Start, v.buf[j].Start) < 0
}
func (v *tombstonesByStartKey) Swap(i, j int) {
	v.buf[i], v.buf[j] = v.buf[j], v.buf[i]
}

type tombstonesByEndKey struct {
	cmp base.Compare
	buf []Tombstone
}

func (v *tombstonesByEndKey) Len() int { return len(v.buf) }
func (v *tombstonesByEndKey) Less(i, j int) bool {
	return v.cmp(v.buf[i].End, v.buf[j].End) < 0
}
func (v *tombstonesByEndKey) Swap(i, j int) {
	v.buf[i], v.buf[j] = v.buf[j], v.buf[i]
}

type tombstonesBySeqNum []Tombstone

func (v *tombstonesBySeqNum) Len() int { return len(*v) }
func (v *tombstonesBySeqNum) Less(i, j int) bool {
	return (*v)[i].Start.SeqNum() > (*v)[j].Start.SeqNum()
}
func (v *tombstonesBySeqNum) Swap(i, j int) {
	(*v)[i], (*v)[j] = (*v)[j], (*v)[i]
}

// Sort the tombstones by start key. This is the ordering required by the
// Fragmenter. Usually tombstones are naturally sorted by their start key, but
// that isn't true for tombstones in the legacy range-del-v1 block format.
func Sort(cmp base.Compare, tombstones []Tombstone) {
	sorter := tombstonesByStartKey{
		cmp: cmp,
		buf: tombstones,
	}
	sort.Sort(&sorter)
}

// Fragmenter fragments a set of range tombstones such that overlapping
// tombstones are split at their overlap points. The fragmented tombstones are
// output to the supplied Output function.
type Fragmenter struct {
	Cmp    base.Compare
	Format base.FormatKey
	// Emit is called to emit a chunk of tombstone fragments. Every tombstone
	// within the chunk has the same start and end key and are in decreasing
	// order of their sequence numbers.
	Emit func([]Tombstone)
	// pending contains the list of pending range tombstone fragments that have
	// not been flushed to the block writer. Note that the tombstones have not
	// been fragmented on the end keys yet. That happens as the tombstones are
	// flushed. All pending tombstones have the same Start.UserKey.
	pending []Tombstone
	// doneBuf is used to buffer completed tombstone fragments when flushing to a
	// specific key (e.g. FlushTo). It is cached in the Fragmenter to allow
	// reuse.
	doneBuf []Tombstone
	// sortBuf is used to sort fragments by end key when flushing.
	sortBuf tombstonesByEndKey
	// flushBuf is used to sort fragments by seqnum before emitting.
	flushBuf tombstonesBySeqNum
	// flushedKey is the key that fragments have been flushed up to. Any
	// additional tombstones added to the fragmenter must have a start key >=
	// flushedKey. A nil value indicates flushedKey has not been set.
	flushedKey []byte
	finished   bool
}

func (f *Fragmenter) checkInvariants(buf []Tombstone) {
	for i := 1; i < len(buf); i++ {
		if f.Cmp(buf[i].Start.UserKey, buf[i].End) >= 0 {
			panic(fmt.Sprintf("pebble: empty pending tombstone invariant violated: %s", buf[i]))
		}
		if f.Cmp(buf[i-1].Start.UserKey, buf[i].Start.UserKey) != 0 {
			panic(fmt.Sprintf("pebble: pending tombstone invariant violated: %s %s",
				buf[i-1].Start.Pretty(f.Format), buf[i].Start.Pretty(f.Format)))
		}
	}
}

// Add adds a tombstone to the fragmenter. Tombstones may overlap and the
// fragmenter will internally split them. The tombstones must be presented in
// increasing start key order. That is, Add must be called with a series of
// tombstones like:
//
//   a---e
//     c---g
//     c-----i
//            j---n
//            j-l
//
// We need to fragment the tombstones at overlap points. In the above
// example, we'd create:
//
//   a-c-e
//     c-e-g
//     c-e-g-i
//            j-l-n
//            j-l
//
// The fragments need to be output sorted by start key, and for equal start
// keys, sorted by descending sequence number. This last part requires a mild
// bit of care as the fragments are not created in descending sequence number
// order.
//
// Once a start key has been seen, we know that we'll never see a smaller
// start key and can thus flush all of the fragments that lie before that
// start key.
//
// Walking through the example above, we start with:
//
//   a---e
//
// Next we add [c,g) resulting in:
//
//   a-c-e
//     c---g
//
// The fragment [a,c) is flushed leaving the pending tombstones as:
//
//   c-e
//   c---g
//
// The next tombstone is [c,i):
//
//   c-e
//   c---g
//   c-----i
//
// No fragments are flushed. The next tombstone is [j,n):
//
//   c-e
//   c---g
//   c-----i
//          j---n
//
// The fragments [c,e), [c,g) and [c,i) are flushed. We sort these fragments
// by their end key, then split the fragments on the end keys:
//
//   c-e
//   c-e-g
//   c-e---i
//
// The [c,e) fragments all get flushed leaving:
//
//   e-g
//   e---i
//
// This process continues until there are no more fragments to flush.
//
// WARNING: the slices backing start.UserKey and end are retained after this
// method returns and should not be modified. This is safe for tombstones that
// are added from a memtable or batch. It is not safe for a tombstone added
// from an sstable where the range-del block has been prefix compressed.
func (f *Fragmenter) Add(start base.InternalKey, end []byte) {
	if f.finished {
		panic("pebble: tombstone fragmenter already finished")
	}
	if f.flushedKey != nil {
		switch c := f.Cmp(start.UserKey, f.flushedKey); {
		case c < 0:
			panic(fmt.Sprintf("pebble: start key (%s) < flushed key (%s)",
				f.Format(start.UserKey), f.Format(f.flushedKey)))
		}
	}
	if f.Cmp(start.UserKey, end) >= 0 {
		// An empty tombstone, we can ignore it.
		return
	}
	if invariants.RaceEnabled {
		f.checkInvariants(f.pending)
		defer func() { f.checkInvariants(f.pending) }()
	}

	if len(f.pending) > 0 {
		// Since all of the pending tombstones have the same start key, we only need
		// to compare against the first one.
		switch c := f.Cmp(f.pending[0].Start.UserKey, start.UserKey); {
		case c > 0:
			panic(fmt.Sprintf("pebble: keys must be added in order: %s > %s",
				f.pending[0].Start.Pretty(f.Format), start.Pretty(f.Format)))
		case c == 0:
			// The new tombstone has the same start key as the existing pending
			// tombstones. Add it to the pending buffer.
			f.pending = append(f.pending, Tombstone{
				Start: start,
				End:   end,
			})
			return
		}

		// At this point we know that the new start key is greater than the pending
		// tombstones start keys.
		f.truncateAndFlush(start.UserKey)
	}

	f.pending = append(f.pending, Tombstone{
		Start: start,
		End:   end,
	})
}

// Deleted returns true if the specified key is covered by one of the pending
// tombstones. The key must be consistent with the ordering of the
// tombstones. That is, it is invalid to specify a key here that is out of
// order with the tombstone start keys passed to Add.
func (f *Fragmenter) Deleted(key base.InternalKey, snapshot uint64) bool {
	if f.finished {
		panic("pebble: tombstone fragmenter already finished")
	}
	if len(f.pending) == 0 {
		return false
	}

	if f.Cmp(f.pending[0].Start.UserKey, key.UserKey) > 0 {
		panic(fmt.Sprintf("pebble: keys must be in order: %s > %s",
			f.pending[0].Start.Pretty(f.Format), key.Pretty(f.Format)))
	}

	seqNum := key.SeqNum()
	for _, t := range f.pending {
		if f.Cmp(key.UserKey, t.End) < 0 {
			// NB: A range deletion tombstone does not delete a point operation at
			// the same sequence number.
			if t.Start.Visible(snapshot) && t.Start.SeqNum() > seqNum {
				return true
			}
		}
	}
	return false
}

// Empty returns true if all fragments added so far have finished flushing.
func (f *Fragmenter) Empty() bool {
	return f.finished || len(f.pending) == 0
}

// FlushTo flushes all of the fragments before key. Used during compaction to
// force emitting of tombstones which straddle an sstable boundary. Note that
// the emitted tombstones are not truncated to the specified key. Consider the
// scenario:
//
//     a---------k#10
//          f#8
//          f#7
//
// If the compaction logic splits f#8 and f#7 into different sstables, we can't
// truncate the tombstone [a,k) at f. Doing so could produce an sstable with
// the records:
//
//     a----f#10
//          f#8
//
// The tombstone [a,f) does not cover the key f.
func (f *Fragmenter) FlushTo(key []byte) {
	if f.finished {
		panic("pebble: tombstone fragmenter already finished")
	}

	if f.flushedKey != nil {
		switch c := f.Cmp(key, f.flushedKey); {
		case c < 0:
			panic(fmt.Sprintf("pebble: flush-to key (%s) < flushed key (%s)",
				f.Format(key), f.Format(f.flushedKey)))
		}
	}
	f.flushedKey = append(f.flushedKey[:0], key...)

	if len(f.pending) > 0 {
		// Since all of the pending tombstones have the same start key, we only need
		// to compare against the first one.
		switch c := f.Cmp(f.pending[0].Start.UserKey, key); {
		case c > 0:
			panic(fmt.Sprintf("pebble: keys must be in order: %s > %s",
				f.Format(f.pending[0].Start.UserKey), f.Format(key)))
		}
		// Note that we explicitly do not return early here if Start.UserKey ==
		// key. Similar to the scenario described above, consider:
		//
		//          f----k#10
		//          f#8
		//          f#7
		//
		// If the compaction logic splits f#8 and f#7 into different sstables, we
		// have to emit the tombstone [f,k) in both sstables.
	}

	// At this point we know that the new start key is greater than the pending
	// tombstones start keys. We flush all tombstone fragments with a start key
	// <= key.
	f.flush(f.pending, key)

	// Truncate the pending tombstones to start with key, filtering any which
	// would become empty.
	pending := f.pending
	f.pending = f.pending[:0]
	for _, t := range pending {
		if f.Cmp(key, t.End) < 0 {
			//   t: a--+--e
			// new:    c------
			f.pending = append(f.pending, Tombstone{
				Start: base.MakeInternalKey(key, t.Start.SeqNum(), t.Start.Kind()),
				End:   t.End,
			})
		}
	}
}

// TruncateAndFlushTo is similar to FlushTo, except it also truncates range
// tombstones to the specified end key by calling truncateAndFlush. Only called
// in compactions where we can guarantee that all versions of UserKeys < key
// have been written, or in other words, where we can ensure we don't split
// a user key across two sstables. Going back to the scenario from above:
//
//    a---------k#10
//         f#8
//         f#7
//
// Let's say the next user key after f is g. Calling TruncateAndFlushTo(g) will
// flush this range tombstone:
//
//    a-------g#10
//         f#8
//         f#7
//
// And leave this one in f.pending:
//
//            g----k#10
//
// WARNING: The fragmenter could hold on to the specified end key. Ensure it's
// a safe byte slice that could outlast the current sstable output, and one
// that will never be modified.
func (f *Fragmenter) TruncateAndFlushTo(key []byte) {
	if f.finished {
		panic("pebble: tombstone fragmenter already finished")
	}
	if f.flushedKey != nil {
		switch c := f.Cmp(key, f.flushedKey); {
		case c < 0:
			panic(fmt.Sprintf("pebble: start key (%s) < flushed key (%s)",
				f.Format(key), f.Format(f.flushedKey)))
		}
	}
	if invariants.RaceEnabled {
		f.checkInvariants(f.pending)
		defer func() { f.checkInvariants(f.pending) }()
	}
	if len(f.pending) > 0 {
		// Since all of the pending tombstones have the same start key, we only need
		// to compare against the first one.
		switch c := f.Cmp(f.pending[0].Start.UserKey, key); {
		case c > 0:
			panic(fmt.Sprintf("pebble: keys must be added in order: %s > %s",
				f.Format(f.pending[0].Start.UserKey), f.Format(key)))
		case c == 0:
			return
		}
	}
	f.truncateAndFlush(key)
}

// Start returns the start key of the first tombstone in the pending buffer,
// or nil if there are no pending tombstones. The start key of all pending
// tombstones is the same as that of the first one.
func (f *Fragmenter) Start() []byte {
	if len(f.pending) > 0 {
		return f.pending[0].Start.UserKey
	}
	return nil
}

// Flushes all pending tombstones up to key (exclusive).
//
// WARNING: The specified key is stored without making a copy, so all callers
// must ensure it is safe.
func (f *Fragmenter) truncateAndFlush(key []byte) {
	f.flushedKey = append(f.flushedKey[:0], key...)
	done := f.doneBuf[:0]
	pending := f.pending
	f.pending = f.pending[:0]

	// pending and f.pending share the same underlying storage. As we iterate
	// over pending we append to f.pending, but only one entry is appended in
	// each iteration, after we have read the entry being overwritten.
	for _, t := range pending {
		if f.Cmp(key, t.End) < 0 {
			//   t: a--+--e
			// new:    c------
			if f.Cmp(t.Start.UserKey, key) < 0 {
				done = append(done, Tombstone{Start: t.Start, End: key})
			}
			f.pending = append(f.pending, Tombstone{
				Start: base.MakeInternalKey(key, t.Start.SeqNum(), t.Start.Kind()),
				End:   t.End,
			})
		} else {
			//   t: a-----e
			// new:       e----
			done = append(done, t)
		}
	}

	f.doneBuf = done[:0]
	f.flush(done, nil)
}

// flush a group of range tombstones to the block. The tombstones are required
// to all have the same start key. We flush all tombstone fragments until
// startKey > lastKey. If lastKey is nil, all tombstone fragments are
// flushed. The specification of a non-nil lastKey occurs during compaction
// where we want to flush (but not truncate) all tombstones that start at or
// before the first key in the next sstable. Consider:
//
//   a---e#10
//   a------h#9
//
// If a compaction splits the sstables at key c we want the first sstable to
// contain the tombstones [a,e)#10 and [a,e)#9. Fragmentation would naturally
// produce a tombstone [e,h)#9, but we don't need to output that tombstone to
// the first sstable.
func (f *Fragmenter) flush(buf []Tombstone, lastKey []byte) {
	if invariants.RaceEnabled {
		f.checkInvariants(buf)
	}

	// Sort the tombstones by end key. This will allow us to walk over the
	// tombstones and easily determine the next split point (the smallest
	// end-key).
	f.sortBuf.cmp = f.Cmp
	f.sortBuf.buf = buf
	sort.Sort(&f.sortBuf)

	// Loop over the range tombstones, splitting by end key.
	for len(buf) > 0 {
		// A prefix of range tombstones will end at split. remove represents the
		// count of that prefix.
		remove := 1
		split := buf[0].End
		f.flushBuf = append(f.flushBuf[:0], buf[0])

		for i := 1; i < len(buf); i++ {
			if f.Cmp(split, buf[i].End) == 0 {
				remove++
			}
			f.flushBuf = append(f.flushBuf, Tombstone{
				Start: buf[i].Start,
				End:   split,
			})
		}

		sort.Sort(&f.flushBuf)
		f.Emit(f.flushBuf)

		if lastKey != nil && f.Cmp(split, lastKey) > 0 {
			break
		}

		// Adjust the start key for every remaining tombstone.
		buf = buf[remove:]
		for i := range buf {
			buf[i].Start.UserKey = split
		}
	}
}

// Finish flushes any remaining fragments to the output. It is an error to call
// this if any other tombstones will be added.
func (f *Fragmenter) Finish() {
	if f.finished {
		panic("pebble: tombstone fragmenter already finished")
	}
	f.flush(f.pending, nil)
	f.finished = true
}
