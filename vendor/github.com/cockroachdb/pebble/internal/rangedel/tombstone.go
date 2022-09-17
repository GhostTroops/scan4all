// Copyright 2018 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package rangedel // import "github.com/cockroachdb/pebble/internal/rangedel"

import (
	"bytes"
	"fmt"

	"github.com/cockroachdb/pebble/internal/base"
)

// Tombstone is a range deletion tombstone. A range deletion tombstone deletes
// all of the keys in the range [start,end). Note that the start key is
// inclusive and the end key is exclusive.
type Tombstone struct {
	Start base.InternalKey
	End   []byte
}

// Overlaps returns 0 if this tombstone overlaps the other, -1 if there's no
// overlap and this tombstone comes before the other, 1 if no overlap and this
// tombstone comes after other.
func (t Tombstone) Overlaps(cmp base.Compare, other Tombstone) int {
	if cmp(t.Start.UserKey, other.Start.UserKey) == 0 && bytes.Equal(t.End, other.End) {
		if other.Start.SeqNum() < t.Start.SeqNum() {
			return -1
		}
		return 1
	}
	if cmp(t.End, other.Start.UserKey) <= 0 {
		return -1
	}
	if cmp(other.End, t.Start.UserKey) <= 0 {
		return 1
	}
	return 0
}

// Empty returns true if the tombstone does not cover any keys.
func (t Tombstone) Empty() bool {
	return t.Start.Kind() != base.InternalKeyKindRangeDelete
}

// Contains returns true if the specified key resides within the range
// tombstone bounds.
func (t Tombstone) Contains(cmp base.Compare, key []byte) bool {
	return cmp(t.Start.UserKey, key) <= 0 && cmp(key, t.End) < 0
}

// Deletes returns true if the tombstone deletes keys at seqNum.
func (t Tombstone) Deletes(seqNum uint64) bool {
	return !t.Empty() && t.Start.SeqNum() > seqNum
}

func (t Tombstone) String() string {
	if t.Empty() {
		return "<empty>"
	}
	return fmt.Sprintf("%s-%s#%d", t.Start.UserKey, t.End, t.Start.SeqNum())
}

// Pretty returns a formatter for the tombstone.
func (t Tombstone) Pretty(f base.FormatKey) fmt.Formatter {
	return prettyTombstone{t, f}
}

type prettyTombstone struct {
	Tombstone
	formatKey base.FormatKey
}

func (t prettyTombstone) Format(s fmt.State, c rune) {
	if t.Empty() {
		fmt.Fprintf(s, "<empty>")
	}
	fmt.Fprintf(s, "%s-%s#%d", t.formatKey(t.Start.UserKey), t.formatKey(t.End), t.Start.SeqNum())
}
