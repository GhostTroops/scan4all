// Copyright 2018 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package rangedel

import "github.com/cockroachdb/pebble/internal/base"

// Iter is an iterator over a set of fragmented tombstones.
type Iter struct {
	cmp        base.Compare
	tombstones []Tombstone
	index      int
}

// Iter implements the base.InternalIterator interface.
var _ base.InternalIterator = (*Iter)(nil)

// NewIter returns a new iterator over a set of fragmented tombstones.
func NewIter(cmp base.Compare, tombstones []Tombstone) *Iter {
	return &Iter{
		cmp:        cmp,
		tombstones: tombstones,
		index:      -1,
	}
}

// SeekGE implements InternalIterator.SeekGE, as documented in the
// internal/base package.
func (i *Iter) SeekGE(key []byte) (*base.InternalKey, []byte) {
	// NB: manually inlined sort.Seach is ~5% faster.
	//
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(index-1) == false, f(upper) == true.
	ikey := base.MakeSearchKey(key)
	i.index = 0
	upper := len(i.tombstones)
	for i.index < upper {
		h := int(uint(i.index+upper) >> 1) // avoid overflow when computing h
		// i.index ≤ h < upper
		if base.InternalCompare(i.cmp, ikey, i.tombstones[h].Start) >= 0 {
			i.index = h + 1 // preserves f(i-1) == false
		} else {
			upper = h // preserves f(j) == true
		}
	}
	// i.index == upper, f(i.index-1) == false, and f(upper) (= f(i.index)) ==
	// true => answer is i.index.
	if i.index >= len(i.tombstones) {
		return nil, nil
	}
	t := &i.tombstones[i.index]
	return &t.Start, t.End
}

// SeekPrefixGE implements InternalIterator.SeekPrefixGE, as documented in the
// internal/base package.
func (i *Iter) SeekPrefixGE(prefix, key []byte, trySeekUsingNext bool) (*base.InternalKey, []byte) {
	// This should never be called as prefix iteration is only done for point records.
	panic("pebble: SeekPrefixGE unimplemented")
}

// SeekLT implements InternalIterator.SeekLT, as documented in the
// internal/base package.
func (i *Iter) SeekLT(key []byte) (*base.InternalKey, []byte) {
	// NB: manually inlined sort.Search is ~5% faster.
	//
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(index-1) == false, f(upper) == true.
	ikey := base.MakeSearchKey(key)
	i.index = 0
	upper := len(i.tombstones)
	for i.index < upper {
		h := int(uint(i.index+upper) >> 1) // avoid overflow when computing h
		// i.index ≤ h < upper
		if base.InternalCompare(i.cmp, ikey, i.tombstones[h].Start) > 0 {
			i.index = h + 1 // preserves f(i-1) == false
		} else {
			upper = h // preserves f(j) == true
		}
	}
	// i.index == upper, f(i.index-1) == false, and f(upper) (= f(i.index)) ==
	// true => answer is i.index.

	// Since keys are strictly increasing, if i.index > 0 then i.index-1 will be
	// the largest whose key is < the key sought.
	i.index--
	if i.index < 0 {
		return nil, nil
	}
	t := &i.tombstones[i.index]
	return &t.Start, t.End
}

// First implements InternalIterator.First, as documented in the internal/base
// package.
func (i *Iter) First() (*base.InternalKey, []byte) {
	if len(i.tombstones) == 0 {
		return nil, nil
	}
	i.index = 0
	t := &i.tombstones[i.index]
	return &t.Start, t.End
}

// Last implements InternalIterator.Last, as documented in the internal/base
// package.
func (i *Iter) Last() (*base.InternalKey, []byte) {
	if len(i.tombstones) == 0 {
		return nil, nil
	}
	i.index = len(i.tombstones) - 1
	t := &i.tombstones[i.index]
	return &t.Start, t.End
}

// Next implements InternalIterator.Next, as documented in the internal/base
// package.
func (i *Iter) Next() (*base.InternalKey, []byte) {
	if i.index == len(i.tombstones) {
		return nil, nil
	}
	i.index++
	if i.index == len(i.tombstones) {
		return nil, nil
	}
	t := &i.tombstones[i.index]
	return &t.Start, t.End
}

// Prev implements InternalIterator.Prev, as documented in the internal/base
// package.
func (i *Iter) Prev() (*base.InternalKey, []byte) {
	if i.index < 0 {
		return nil, nil
	}
	i.index--
	if i.index < 0 {
		return nil, nil
	}
	t := &i.tombstones[i.index]
	return &t.Start, t.End
}

// Key implements InternalIterator.Key, as documented in the internal/base
// package.
func (i *Iter) Key() *base.InternalKey {
	return &i.tombstones[i.index].Start
}

// Value implements InternalIterator.Value, as documented in the internal/base
// package.
func (i *Iter) Value() []byte {
	return i.tombstones[i.index].End
}

// Valid implements InternalIterator.Valid, as documented in the internal/base
// package.
func (i *Iter) Valid() bool {
	return i.index >= 0 && i.index < len(i.tombstones)
}

// Error implements InternalIterator.Error, as documented in the internal/base
// package.
func (i *Iter) Error() error {
	return nil
}

// Close implements InternalIterator.Close, as documented in the internal/base
// package.
func (i *Iter) Close() error {
	return nil
}

// SetBounds implements InternalIterator.SetBounds, as documented in the
// internal/base package.
func (i *Iter) SetBounds(lower, upper []byte) {
	// This should never be called as bounds are only used for point records.
	panic("pebble: SetBounds unimplemented")
}

func (i *Iter) String() string {
	return "range-del"
}
