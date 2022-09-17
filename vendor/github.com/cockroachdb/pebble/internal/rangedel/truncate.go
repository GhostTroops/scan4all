// Copyright 2019 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package rangedel

import "github.com/cockroachdb/pebble/internal/base"

// Truncate creates a new iterator where every tombstone in the supplied
// iterator is truncated to be contained within the range [lower, upper).
// If start and end are specified, filter out any range tombstones that
// are completely outside those bounds.
func Truncate(
	cmp base.Compare,
	iter base.InternalIterator,
	lower, upper []byte,
	start, end *base.InternalKey,
) *Iter {
	var tombstones []Tombstone
	for key, value := iter.First(); key != nil; key, value = iter.Next() {
		t := Tombstone{
			Start: *key,
			End:   value,
		}
		// Ignore this tombstone if it lies completely outside [start, end].
		// The comparison between t.End and start is by user key only, as
		// the range tombstone is exclusive at t.End, so comparing by user keys
		// is sufficient. Alternatively, the below comparison can be seen to
		// be logically equivalent to:
		// InternalKey{UserKey: t.End, SeqNum: SeqNumMax} < start
		if start != nil && cmp(t.End, start.UserKey) <= 0 {
			continue
		}
		if end != nil && base.InternalCompare(cmp, t.Start, *end) > 0 {
			continue
		}
		if cmp(t.Start.UserKey, lower) < 0 {
			t.Start.UserKey = lower
		}
		if cmp(t.End, upper) > 0 {
			t.End = upper
		}
		if cmp(t.Start.UserKey, t.End) < 0 {
			tombstones = append(tombstones, t)
		}
	}
	return NewIter(cmp, tombstones)
}
