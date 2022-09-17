// Copyright 2018 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package rangedel

import "github.com/cockroachdb/pebble/internal/base"

// SeekGE seeks to the newest tombstone that contains or is past the target
// key. The snapshot parameter controls the visibility of tombstones (only
// tombstones older than the snapshot sequence number are visible). The
// iterator must contain fragmented tombstones: any overlapping tombstones must
// have the same start and end key. The position of the iterator is undefined
// after calling SeekGE and may not be pointing at the returned tombstone.
func SeekGE(cmp base.Compare, iter base.InternalIterator, key []byte, snapshot uint64) Tombstone {
	// NB: We use SeekLT in order to land on the proper tombstone for a search
	// key that resides in the middle of a tombstone. Consider the scenario:
	//
	//     a---e
	//         e---i
	//
	// The tombstones are indexed by their start keys `a` and `e`. If the
	// search key is `c` we want to land on the tombstone [a,e). If we were to
	// use SeekGE then the search key `c` would land on the tombstone [e,i) and
	// we'd have to backtrack. The one complexity here is what happens for the
	// search key `e`. In that case SeekLT will land us on the tombstone [a,e)
	// and we'll have to move forward.
	iterKey, iterValue := iter.SeekLT(key)

	// Invariant: key < iter.Key().UserKey

	if iterKey != nil && cmp(key, iterValue) < 0 {
		// The current tombstones contains or is past the search key, but SeekLT
		// returns the oldest entry for a key, so backup until we hit the previous
		// tombstone or an entry which is not visible.
		for savedKey := iterKey.UserKey; ; {
			iterKey, iterValue = iter.Prev()
			if iterKey == nil || cmp(savedKey, iterValue) >= 0 || !iterKey.Visible(snapshot) {
				iterKey, iterValue = iter.Next()
				break
			}
		}
	} else {
		// The current tombstone lies before the search key. Advance the iterator
		// to the next tombstone which is guaranteed to lie at or past the search
		// key.
		iterKey, iterValue = iter.Next()
		if iterKey == nil {
			// We've run out of tombstones.
			return Tombstone{}
		}
	}

	// The iter is positioned at a non-nil iterKey which is the earliest iterator
	// position that satisfies the requirement that it contains or is past the
	// target key. But it may not be visible based on the snapshot. So now we
	// only need to move forward and return the first tombstone that is visible.
	//
	// Walk through the tombstones to find one the newest one that is visible
	// (i.e. has a sequence number less than the snapshot sequence number).
	for {
		if start := iterKey; start.Visible(snapshot) {
			// The tombstone is visible at our read sequence number.
			return Tombstone{
				Start: *start,
				End:   iterValue,
			}
		}
		iterKey, iterValue = iter.Next()
		if iterKey == nil {
			// We've run out of tombstones.
			return Tombstone{}
		}
	}
}

// SeekLE seeks to the newest tombstone that contains or is before the target
// key. The snapshot parameter controls the visibility of tombstones (only
// tombstones older than the snapshot sequence number are visible). The
// iterator must contain fragmented tombstones: any overlapping tombstones must
// have the same start and end key. The position of the iterator is undefined
// after calling SeekLE and may not be pointing at the returned tombstone.
func SeekLE(cmp base.Compare, iter base.InternalIterator, key []byte, snapshot uint64) Tombstone {
	// NB: We use SeekLT in order to land on the proper tombstone for a search
	// key that resides in the middle of a tombstone. Consider the scenario:
	//
	//     a---e
	//         e---i
	//
	// The tombstones are indexed by their start keys `a` and `e`. If the
	// search key is `c` we want to land on the tombstone [a,e). If we were to
	// use SeekGE then the search key `c` would land on the tombstone [e,i) and
	// we'd have to backtrack. The one complexity here is what happens for the
	// search key `e`. In that case SeekLT will land us on the tombstone [a,e)
	// and we'll have to move forward.
	iterKey, iterValue := iter.SeekLT(key)

	// Consider the following set of fragmented tombstones, ordered by increasing
	// key and decreasing seqnum:
	//
	//   2:   d---h
	//   1:   d---h
	//   2:         j---n
	//   1:         j---n
	//   2:             n---r
	//   1:             n---r
	//
	// The cases to consider:
	//
	// 1. search-key == "a"
	//   - The search key is fully before any tombstone. We should return an
	//     empty tombstone. The initial SeekLT("a") will return iterKey==nil and
	//     the next tombstone [d,h) lies fully after the search key.
	//
	// 2. search-key == "d"
	//   - The search key is contained by the tombstone [d,h). We want to return
	//     the newest version of the tombstone [d,h) or the empty tombstone if
	//     there are no visible versions. The initial SeekLT("d") will return
	//     iterKey==nil and the next tombstone [d,h) contains the search key. We
	//     iterate forward from there returning the newest visible tombstone for
	//     [d, h) and if there is no visible one return an empty tombstone.
	//
	// 3. search-key == "h" or "i"
	//   - The search key lies between the tombstones [d,h) and [j,n). We want to
	//     return the newest visible version of the tombstone [d,h) or the empty
	//     tombstone if there are no visible versions. The initial SeekLT("h") or
	//     SeekLT("i") will return the tombstone [d,h)#1. Because the end key of
	//     this tombstone is less than or equal to the search key we have to
	//     check if the next tombstone contains the search key. In this case it
	//     does not and we need to look backwards starting from [d, h)#1, falling
	//     into case 5.
	//
	// 4. search-key == "n"
	//   - The search key is contained by the tombstone [n,r). We want to return
	//     the newest version of the tombstone [n,r) or an earlier tombstone if
	//     there are no visible versions of [n,r). The initial SeekLT("n") will
	//     return the tombstone [j,n)#1. Because the end key of the tombstone
	//     [j,n) equals the search key "n" we have to see if the next tombstone
	//     contains the search key (which it does). We iterate forward through
	//     the [n,r) tombstones (not beyond) and return the first visible
	//     tombstone (since this iteration is going from newer to older). If
	//     there are no visible [n,r) tombstones (due to the snapshot parameter)
	//     we need to step back to [n,r) and look backwards, falling into case 5.
	//
	// 5. search-key == "p"
	//   - The search key is contained by the tombstone [n,r). We want to return
	//     the newest visible version of the tombstone [n,r) or an earlier
	//     tombstone if there are no visible versions. Because the end key of the
	//     tombstone [n,r) is greater than the search key "p", we do not have to
	//     look at the next tombstone. We iterate backwards starting with [n,r),
	//     then [j,n) and then [d,h), returning the newest version of the first
	//     visible tombstone.

	switch {
	case iterKey == nil:
		// Cases 1 and 2. Advance the iterator until we find a visible version, we
		// exhaust the iterator, or we hit the next tombstone.
		for {
			iterKey, iterValue = iter.Next()
			if iterKey == nil || cmp(key, iterKey.UserKey) < 0 {
				// The iterator is exhausted or we've hit the next tombstone.
				return Tombstone{}
			}
			if start := iterKey; start.Visible(snapshot) {
				return Tombstone{
					Start: *start,
					End:   iterValue,
				}
			}
		}

	default:
		// Invariant: key > iterKey.UserKey
		if cmp(key, iterValue) >= 0 {
			// Cases 3 and 4 (forward search). The current tombstone lies before the
			// search key. Check to see if the next tombstone contains the search
			// key. If it doesn't, we'll backup and look for an earlier tombstone.
			iterKey, iterValue = iter.Next()
			if iterKey == nil || cmp(key, iterKey.UserKey) < 0 {
				// Case 3. The next tombstone is past our search key (or there is no next
				// tombstone).
				iterKey, iterValue = iter.Prev()
			} else {
				// Case 4. Advance the iterator until we find a visible version or we hit
				// the next tombstone.
				for {
					if start := iterKey; start.Visible(snapshot) {
						// We've found our tombstone as we know earlier tombstones are
						// either not visible or lie before this tombstone.
						return Tombstone{
							Start: *start,
							End:   iterValue,
						}
					}
					iterKey, iterValue = iter.Next()
					if iterKey == nil || cmp(key, iterKey.UserKey) < 0 {
						// There is no next tombstone, or the next tombstone is past our
						// search key. Back up to the previous tombstone. Note that we'll
						// immediately fall into the loop below which will keep on
						// iterating backwards until we find a visible tombstone and that
						// tombstone must contain or be before our search key.
						iterKey, iterValue = iter.Prev()
						break
					}
				}
			}
		}

		// Cases 3, 4, and 5 (backwards search). We're positioned at a tombstone
		// that contains or is before the search key. Walk backward until we find a
		// visible tombstone from this point.
		for !iterKey.Visible(snapshot) {
			iterKey, iterValue = iter.Prev()
			if iterKey == nil {
				// No visible tombstones before our search key.
				return Tombstone{}
			}
		}

		// We're positioned at a tombstone that contains or is before the search
		// key and is visible. Walk backwards until we find the latest version of
		// this tombstone that is visible (i.e. has a sequence number less than the
		// snapshot sequence number).
		t := Tombstone{Start: *iterKey, End: iterValue} // current candidate to return
		for {
			iterKey, _ = iter.Prev()
			if iterKey == nil {
				// We stepped off the end of the iterator.
				break
			}
			if !iterKey.Visible(snapshot) {
				// The previous tombstone is not visible.
				break
			}
			if cmp(t.Start.UserKey, iterKey.UserKey) != 0 {
				// The previous tombstone is before our candidate tombstone.
				break
			}
			// Update the candidate tombstone's seqnum. NB: The end key is guaranteed
			// to be the same.
			t.Start.Trailer = iterKey.Trailer
		}
		return t
	}
}
