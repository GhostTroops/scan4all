// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package golden

import (
	"cmp"
	"fmt"
	"iter"
	"net/netip"
	"slices"
)

// cmpPrefix, helper function, compare func for prefix sort,
// all cidrs are already normalized
func cmpPrefix(a, b netip.Prefix) int {
	if cmpAddr := a.Addr().Compare(b.Addr()); cmpAddr != 0 {
		return cmpAddr
	}
	return cmp.Compare(a.Bits(), b.Bits())
}

// Table is a linear, un-optimized routing table implemented as a slice of
// prefix-value pairs. It serves as a simple, easy-to-verify golden reference
// for testing complex routing table implementations (like BART).
type Table[V any] []TableItem[V]

// TableItem represents a single entry in the routing table, mapping a masked
// IP prefix to a associated value.
type TableItem[V any] struct {
	Pfx netip.Prefix
	Val V
}

// String returns a human-readable representation of the TableItem.
func (g TableItem[V]) String() string {
	return fmt.Sprintf("(%s, %v)", g.Pfx, g.Val)
}

// Insert adds or updates a prefix-value mapping in the table.
// The prefix is normalized (masked) before insertion.
func (t *Table[V]) Insert(pfx netip.Prefix, val V) {
	pfx = pfx.Masked()
	for i, item := range *t {
		if item.Pfx == pfx {
			(*t)[i].Val = val // update existing entry
			return
		}
	}
	*t = append(*t, TableItem[V]{Pfx: pfx, Val: val})
}

// Delete removes the specified prefix from the table.
// Returns true if the prefix was present and removed, false otherwise.
func (t *Table[V]) Delete(pfx netip.Prefix) (exists bool) {
	pfx = pfx.Masked()

	for i, item := range *t {
		if item.Pfx == pfx {
			*t = slices.Delete(*t, i, i+1)
			return true
		}
	}
	return false
}

// AllSorted returns a sorted list of all prefixes currently present in the table.
// The order is determined by prefix network address first, then mask length.
func (t Table[V]) AllSorted() []netip.Prefix {
	result := make([]netip.Prefix, 0, len(t))

	for _, item := range t {
		result = append(result, item.Pfx)
	}
	slices.SortFunc(result, cmpPrefix)
	return result
}

// All returns a list of all prefix, value pairs currently present
// in the table as iterator.
func (t Table[V]) All() iter.Seq2[netip.Prefix, V] {
	return func(yield func(pfx netip.Prefix, val V) bool) {
		for _, item := range t {
			if !yield(item.Pfx, item.Val) {
				return
			}
		}
	}
}

// Get performs an exact match search for the given prefix.
func (t Table[V]) Get(pfx netip.Prefix) (val V, ok bool) {
	pfx = pfx.Masked()
	for _, item := range t {
		if item.Pfx == pfx {
			return item.Val, true
		}
	}
	return val, false
}

// Update modifies an existing prefix or inserts a new one using a callback function.
// The callback receives the current value (or zero value) and a boolean indicating
// whether the prefix was found. Returns the newly set value.
func (t *Table[V]) Update(pfx netip.Prefix, cb func(V, bool) V) (val V) {
	pfx = pfx.Masked()
	for i, item := range *t {
		if item.Pfx == pfx {
			val = cb(item.Val, true)
			(*t)[i].Val = val
			return val
		}
	}

	val = cb(val, false)
	*t = append(*t, TableItem[V]{Pfx: pfx, Val: val})
	return val
}

// Union merges entries from tb into ta. Entries in tb override matching prefixes in ta.
func (ta *Table[V]) Union(tb *Table[V]) {
	for _, bItem := range *tb {
		var match bool
		for i, aItem := range *ta {
			if aItem.Pfx == bItem.Pfx {
				(*ta)[i] = bItem
				match = true
				break
			}
		}
		if !match {
			*ta = append(*ta, bItem)
		}
	}
}

// Lookup performs a Longest Prefix Match (LPM) for the given IP address.
func (t Table[V]) Lookup(addr netip.Addr) (val V, ok bool) {
	bestLen := -1

	for _, item := range t {
		if item.Pfx.Bits() > bestLen && item.Pfx.Contains(addr) {
			val = item.Val
			ok = true
			bestLen = item.Pfx.Bits()
		}
	}
	return val, ok
}

// LookupPrefix performs a Longest Prefix Match (LPM) for a covering prefix.
// It returns the value associated with the most specific prefix that covers pfx.
func (t Table[V]) LookupPrefix(pfx netip.Prefix) (val V, ok bool) {
	_, val, ok = t.LookupPrefixLPM(pfx)
	return val, ok
}

// LookupPrefixLPM performs a Longest Prefix Match (LPM) for a covering prefix.
// It returns the matched covering prefix, its associated value, and a boolean status.
func (t Table[V]) LookupPrefixLPM(pfx netip.Prefix) (lpm netip.Prefix, val V, ok bool) {
	pfx = pfx.Masked()
	bestLen := -1

	for _, item := range t {
		// A prefix covers pfx if they overlap and item.Pfx is equal to or shorter (broader) than pfx.
		if item.Pfx.Bits() <= pfx.Bits() && item.Pfx.Bits() > bestLen && item.Pfx.Overlaps(pfx) {
			val = item.Val
			lpm = item.Pfx
			ok = true
			bestLen = item.Pfx.Bits()
		}
	}
	return lpm, val, ok
}

// Subnets returns all prefixes in the table that are subnets of (covered by) pfx,
// sorted in canonical prefix order.
func (t Table[V]) Subnets(pfx netip.Prefix) []netip.Prefix {
	pfx = pfx.Masked()
	var result []netip.Prefix

	for _, item := range t {
		if pfx.Bits() <= item.Pfx.Bits() && pfx.Overlaps(item.Pfx) {
			result = append(result, item.Pfx)
		}
	}
	slices.SortFunc(result, cmpPrefix)
	return result
}

// Supernets returns all covering prefixes (supernets) for pfx contained in the table,
// ordered from most-specific to least-specific (longest to shortest mask length).
func (t Table[V]) Supernets(pfx netip.Prefix) []netip.Prefix {
	pfx = pfx.Masked()
	var result []netip.Prefix

	for _, item := range t {
		if item.Pfx.Bits() <= pfx.Bits() && item.Pfx.Overlaps(pfx) {
			result = append(result, item.Pfx)
		}
	}
	slices.SortFunc(result, cmpPrefix)
	slices.Reverse(result)
	return result
}

// OverlapsPrefix reports whether any prefix in the table overlaps with pfx.
func (t Table[V]) OverlapsPrefix(pfx netip.Prefix) bool {
	pfx = pfx.Masked()
	for _, item := range t {
		if item.Pfx.Overlaps(pfx) {
			return true
		}
	}
	return false
}

// Overlaps reports whether any prefix in ta overlaps with any prefix in tb.
func (ta Table[V]) Overlaps(tb *Table[V]) bool {
	for _, aItem := range ta {
		for _, bItem := range *tb {
			if aItem.Pfx.Overlaps(bItem.Pfx) {
				return true
			}
		}
	}
	return false
}

// Sort orders the table in-place by prefix (IP address first, then prefix length).
func (t *Table[V]) Sort() {
	slices.SortFunc(*t, func(a, b TableItem[V]) int {
		return cmpPrefix(a.Pfx, b.Pfx)
	})
}

// Aggregate compresses the Table in-place by merging overlapping and
// adjacent IP prefixes into their minimal covering CIDR blocks.
func (t *Table[V]) Aggregate() {
	if len(*t) <= 1 {
		return
	}

	tableItemsSort := func(a, b TableItem[V]) int { return cmpPrefix(a.Pfx, b.Pfx) }

	if !slices.IsSortedFunc(*t, tableItemsSort) {
		slices.SortFunc(*t, tableItemsSort)
	}

	buf := make([]TableItem[V], 0, len(*t))

	// Iteratively merge entries until no further aggregation is possible
	for {
		loop := false

		// reset buffer
		buf = buf[:0]

		for i := range len(*t) {
			thisItem := (*t)[i]

			// first result item
			if len(buf) == 0 {
				buf = append(buf, thisItem)
				continue
			}

			lastIdx := len(buf) - 1
			lastItem := &buf[lastIdx]

			// Only aggregate prefixes belonging to the same IP family
			if lastItem.Pfx.Addr().Is4() != thisItem.Pfx.Addr().Is4() {
				buf = append(buf, thisItem)
				continue
			}

			// Rule 1: Overlapping / Containment
			// Since cmpPrefix places broader prefixes first for identical start addresses,
			// last covers this if last contains this's network address
			if lastItem.Pfx.Contains(thisItem.Pfx.Addr()) {
				// this covered item gets dropped
				loop = true
				continue
			}

			// Rule 2: Adjacency (merging sibling prefixes)
			// Equal prefix length + both share a common super prefix of length (bits - 1)
			if lastItem.Pfx.Bits() == thisItem.Pfx.Bits() && lastItem.Pfx.Bits() > 0 {
				super, err := lastItem.Pfx.Addr().Prefix(lastItem.Pfx.Bits() - 1)
				if err == nil && super.Contains(thisItem.Pfx.Addr()) {
					// Merge into parent block
					lastItem.Pfx = super
					loop = true
					continue
				}
			}

			buf = append(buf, thisItem)
		}

		*t = buf

		if !loop {
			clear(buf[len(buf):cap(buf)])
			break
		}
	}
}
