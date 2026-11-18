// Code generated from file "commonmethods_tmpl.go"; DO NOT EDIT.

// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package bart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/gaissmai/bart/internal/art"
	"github.com/gaissmai/bart/internal/lpm"
	"github.com/gaissmai/bart/internal/nodes"
	"github.com/gaissmai/bart/internal/value"
)

// rootNodeByVersion, root node getter for ip version.
func (f *liteTable[V]) rootNodeByVersion(is4 bool) *nodes.LiteNode[V] {
	if is4 {
		return &f.root4
	}
	return &f.root6
}

func (t *liteTable[V]) sizeUpdate(is4 bool, delta int) {
	if is4 {
		t.size4 += delta
		return
	}
	t.size6 += delta
}

// Contains reports whether any stored prefix covers the given IP address.
// It returns false for invalid IP addresses.
//
// This method performs longest-prefix matching and returns true if any prefix
// in the routing table contains the IP address, regardless of the associated value.
//
// It does not return the value or prefix of the matching item, but as a test
// against an allow/deny list, it is often sufficient and a few nanoseconds
// faster than Lookup.
//
// Any IPv6 zone identifier is stripped and has no effect on the lookup result.
func (f *liteTable[V]) Contains(ip netip.Addr) bool {
	// speed is top priority: no explicit test for ip.IsValid
	// if ip is invalid, AsSlice() returns nil, Contains returns false.
	is4 := ip.Is4()

	n := f.rootNodeByVersion(is4)

	for _, octet := range ip.AsSlice() {
		// for contains, any lpm match is good enough, no backtracking needed
		if n.PrefixCount() != 0 && n.Contains(art.OctetToIdx(octet)) {
			return true
		}

		// stop traversing?
		if !n.Children.Test(octet) {
			return false
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *nodes.LiteNode[V]:
			n = kid // descend down to next trie level

		case *nodes.FringeNode[V]:
			// fringe is the default-route for all possible octets below
			return true

		case *nodes.LeafNode[V]:
			// Strip IPv6 zone before netip.Prefix.Contains to prevent false returns.
			if !is4 {
				// but netip.Addr.withoutZone  is not exported :-(
				// and netip.Addr.WithZone("") is not inlinable, so we have to resort to this clever trick:
				// https://github.com/gaissmai/bart/pull/418#issuecomment-5735613506
				ip = netip.PrefixFrom(ip, 0).Addr()
			}

			return kid.Prefix.Contains(ip)
		}
	}

	return false
}

// Lookup performs a longest-prefix match (LPM) lookup for the given address.
// It returns the associated value (payload) and true if a matching prefix is found.
// It returns the zero value and false for invalid IP addresses or if no prefix contains the address.
//
// This is the fundamental operation for IP routing decisions, finding the
// best matching route (the most specific longest prefix) for a destination address.
//
// Any IPv6 zone identifier is stripped and has no effect on the lookup result.
func (t *liteTable[V]) Lookup(ip netip.Addr) (val V, ok bool) {
	is4 := ip.Is4()
	octets := ip.AsSlice()
	n := t.rootNodeByVersion(is4)

	// stack of the traversed nodes for fast backtracking, if needed
	stack := [nodes.MaxTreeDepth]*nodes.LiteNode[V]{}

	// run variable, used after for loop
	var depth int
	var octet byte

LOOP:
	// find leaf node
	for depth, octet = range octets {
		depth &= nodes.DepthMask // BCE, Lookup must be fast

		// push current node on stack for fast backtracking
		stack[depth] = n

		// go down in tight loop to last octet
		if !n.Children.Test(octet) {
			// no more nodes below octet
			break LOOP
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *nodes.LiteNode[V]:
			n = kid
			continue LOOP // descend down to next trie level

		case *nodes.FringeNode[V]:
			// fringe is the default-route for all possible nodes below
			return kid.Value, true

		case *nodes.LeafNode[V]:
			// Strip IPv6 zone before netip.Prefix.Contains to prevent false returns.
			if !is4 {
				// but netip.Addr.withoutZone  is not exported :-(
				// and netip.Addr.WithZone("") is not inlinable, so we have to resort to this clever trick:
				// https://github.com/gaissmai/bart/pull/418#issuecomment-5735613506
				ip = netip.PrefixFrom(ip, 0).Addr()
			}

			if kid.Prefix.Contains(ip) {
				return kid.Value, true
			}
			// reached a path compressed prefix, stop traversing
			break LOOP
		}
	}

	// Hot-path optimization: delay ip.IsValid() check until after traversal.
	// Fast path: if a Fringe or Leaf matches early in LOOP, we return without ever checking IsValid().
	// Slow path: for invalid IPs, range over nil octets is a no-op (stack[0] stays nil).
	// We validate now before backtracking to avoid a nil pointer panic on n.PrefixCount().
	if !ip.IsValid() {
		return val, ok
	}

	// start backtracking, unwind the stack, bounds check eliminated
	for ; depth >= 0; depth-- {
		depth &= nodes.DepthMask // BCE

		n = stack[depth]

		// longest prefix match, skip if node has no prefixes
		if n.PrefixCount() != 0 {
			idx := art.OctetToIdx(octets[depth])
			// lookupIdx() manually inlined
			if lpmIdx, ok2 := n.Prefixes.AndTop(&lpm.LookupTbl[idx]); ok2 {
				return n.MustGetPrefix(lpmIdx), ok2
			}
		}
	}

	return val, ok
}

// LookupPrefix performs a longest prefix match lookup for any address within
// the given prefix. It finds the most specific routing table entry that would
// match any address in the provided prefix range.
//
// This is functionally identical to LookupPrefixLPM but returns only the
// associated value, not the matching prefix itself.
//
// Returns the value and true if a matching prefix is found.
// Returns zero value and false if no match exists.
func (t *liteTable[V]) LookupPrefix(pfx netip.Prefix) (val V, ok bool) {
	_, val, ok = t.lookupPrefixLPM(pfx, false)
	return val, ok
}

// LookupPrefixLPM performs a longest prefix match lookup for any address within
// the given prefix. It finds the most specific routing table entry that would
// match any address in the provided prefix range.
//
// This is functionally identical to LookupPrefix but additionally returns the
// matching LPM prefix itself along with the value.
//
// This method is slower than LookupPrefix and should only be used if the
// matching lpm entry is also required for other reasons.
//
// Returns the matching prefix, its associated value, and true if found.
// Returns zero values and false if no match exists.
func (t *liteTable[V]) LookupPrefixLPM(pfx netip.Prefix) (lpmPfx netip.Prefix, val V, ok bool) {
	return t.lookupPrefixLPM(pfx, true)
}

func (t *liteTable[V]) lookupPrefixLPM(pfx netip.Prefix, withLPM bool) (lpmPfx netip.Prefix, val V, ok bool) {
	if !pfx.IsValid() {
		return lpmPfx, val, ok
	}

	// canonicalize the prefix
	pfx = pfx.Masked()

	ip := pfx.Addr()
	pfxLen := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	strideCount, modBits := nodes.DivMod8(pfxLen)

	n := t.rootNodeByVersion(is4)

	// record path to leaf node
	stack := [nodes.MaxTreeDepth]*nodes.LiteNode[V]{}

	var depth int
	var octet byte

LOOP:
	// find the last node on the octets path in the trie,
	for depth, octet = range octets {
		depth &= nodes.DepthMask // BCE

		// stepped one past the last stride of interest; back up to last and break
		if depth > strideCount {
			depth--
			break
		}
		// push current node on stack
		stack[depth] = n

		// go down in tight loop to leaf node
		if !n.Children.Test(octet) {
			break LOOP
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *nodes.LiteNode[V]:
			n = kid
			continue LOOP // descend down to next trie level

		case *nodes.LeafNode[V]:
			// reached a path compressed prefix, stop traversing
			if kid.Prefix.Bits() > pfxLen || !kid.Prefix.Contains(ip) {
				break LOOP
			}
			return kid.Prefix, kid.Value, true

		case *nodes.FringeNode[V]:
			// the bits of the fringe are defined by the depth
			// maybe the LPM isn't needed, saves some cycles
			fringeBits := (depth + 1) << 3
			if fringeBits > pfxLen {
				break LOOP
			}

			// the LPM isn't needed, saves some cycles
			if !withLPM {
				return netip.Prefix{}, kid.Value, true
			}

			// get the LPM prefix back from ip and depth
			// it's a fringe, bits are always /8, /16, /24, ...
			fringePfx, _ := ip.Prefix((depth + 1) << 3)
			return fringePfx, kid.Value, true
		}
	}

	// start backtracking, unwind the stack
	for ; depth >= 0; depth-- {
		depth &= nodes.DepthMask // BCE

		n = stack[depth]

		// longest prefix match, skip if node has no prefixes
		if n.PrefixCount() == 0 {
			continue
		}

		var idx uint8
		octet = octets[depth]

		// only the final stride may have a different prefix len
		// all others are just host routes
		if depth == strideCount {
			idx = art.PfxToIdx(octet, modBits)
		} else {
			idx = art.OctetToIdx(octet)
		}

		// manually inlined: lookupIdx(idx)
		var topIdx uint8
		if topIdx, ok = n.Prefixes.AndTop(&lpm.LookupTbl[idx]); ok {
			val = n.MustGetPrefix(topIdx)

			// called from LookupPrefix
			if !withLPM {
				return netip.Prefix{}, val, ok
			}

			// called from LookupPrefixLPM

			// get the bits from depth and top idx
			pfxBits := int(art.PfxBits(depth, topIdx))

			// calculate the lpmPfx from incoming ip and new mask
			// netip.Addr.Prefix canonicalizes. Invariant: art.PfxBits(depth, topIdx)
			// yields a valid mask (v4: 0..32, v6: 0..128), so error is impossible.
			lpmPfx, _ = ip.Prefix(pfxBits)
			return lpmPfx, val, ok
		}
	}

	return lpmPfx, val, ok
}

// Insert adds or updates a prefix-value pair in the routing table.
// If the prefix already exists, its value is updated; otherwise a new entry is created.
// Invalid prefixes are silently ignored.
//
// The prefix is automatically canonicalized using pfx.Masked() to ensure
// consistent behavior regardless of host bits in the input.
func (t *liteTable[V]) Insert(pfx netip.Prefix, val V) {
	if !pfx.IsValid() {
		return
	}

	// canonicalize prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()
	n := t.rootNodeByVersion(is4)

	if exists := n.Insert(pfx, val, 0); exists {
		return
	}

	// true insert, update size
	t.sizeUpdate(is4, 1)
}

// InsertPersist is similar to Insert but the receiver isn't modified.
//
// All nodes touched during insert are cloned and a new trie is returned.
// This is not a full [liteTable.Clone], all untouched nodes are still referenced
// from both tries.
//
// If the payload type V contains pointers or needs deep copying,
// it must implement the Clone method to support correct cloning.
//
// Due to cloning overhead this is significantly slower than Insert,
// typically taking μsec instead of nsec.
func (t *liteTable[V]) InsertPersist(pfx netip.Prefix, val V) *liteTable[V] {
	if !pfx.IsValid() {
		return t
	}

	// canonicalize prefix
	pfx = pfx.Masked()
	is4 := pfx.Addr().Is4()

	// share size counters; root nodes cloned selectively.
	pt := &liteTable[V]{
		size4: t.size4,
		size6: t.size6,
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	// Clone root node corresponding to the IP version, for copy-on-write.
	n := &pt.root4

	if is4 {
		pt.root4 = *t.root4.CloneFlat(cloneFn)
		pt.root6 = t.root6
	} else {
		pt.root4 = t.root4
		pt.root6 = *t.root6.CloneFlat(cloneFn)

		n = &pt.root6
	}

	if !n.InsertPersist(cloneFn, pfx, val, 0) {
		pt.sizeUpdate(is4, 1)
	}

	return pt
}

// Delete removes the exact prefix pfx from the table in-place.
//
// This is an exact-match operation (no LPM). If pfx exists, the entry is
// removed. If pfx does not exist or pfx is invalid, the table is left unchanged.
//
// The prefix is canonicalized (Masked) before lookup.
func (t *liteTable[V]) Delete(pfx netip.Prefix) {
	if !pfx.IsValid() {
		return
	}

	// canonicalize prefix
	pfx = pfx.Masked()
	is4 := pfx.Addr().Is4()

	n := t.rootNodeByVersion(is4)
	if exists := n.Delete(pfx); exists {
		t.sizeUpdate(is4, -1)
	}
}

// Get performs an exact-prefix lookup and returns whether the exact
// prefix exists. The prefix is canonicalized (Masked) before lookup.
//
// This is an exact-match operation (no LPM). The prefix must match exactly
// in both address and prefix length to be found. If pfx exists, the
// associated value (zero value for Lite) and found=true is returned.
// If pfx does not exist or pfx is invalid, the zero value for V and
// exists=false is returned.
//
// For longest-prefix-match (LPM) lookups, use Contains(ip), Lookup(ip),
// LookupPrefix(pfx) or LookupPrefixLPM(pfx) instead.
func (t *liteTable[V]) Get(pfx netip.Prefix) (val V, exists bool) {
	if !pfx.IsValid() {
		return val, exists
	}
	// canonicalize prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()
	n := t.rootNodeByVersion(is4)

	return n.Get(pfx)
}

// DeletePersist is similar to Delete but does not modify the receiver.
//
// It performs a copy-on-write delete operation, cloning all nodes touched during
// deletion and returning a new liteTable reflecting the change.
//
// If the prefix is invalid or doesn't exist, the original table is
// returned unchanged.
//
// If the payload type V contains pointers or requires deep copying,
// it must implement the Clone method for correct cloning.
//
// Due to cloning overhead this is significantly slower than Delete,
// typically taking μsec instead of nsec.
func (t *liteTable[V]) DeletePersist(pfx netip.Prefix) *liteTable[V] {
	if !pfx.IsValid() {
		return t
	}

	// canonicalize prefix
	pfx = pfx.Masked()
	is4 := pfx.Addr().Is4()

	// Preflight check: avoid cloning if prefix doesn't exist
	n := t.rootNodeByVersion(is4)
	if _, found := n.Get(pfx); !found {
		return t
	}

	// share size counters; root nodes cloned selectively.
	pt := &liteTable[V]{
		size4: t.size4,
		size6: t.size6,
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	// Clone root node corresponding to the IP version, for copy-on-write.
	if is4 {
		pt.root4 = *t.root4.CloneFlat(cloneFn)
		pt.root6 = t.root6
		n = &pt.root4
	} else {
		pt.root4 = t.root4
		pt.root6 = *t.root6.CloneFlat(cloneFn)
		n = &pt.root6
	}

	if exists := n.DeletePersist(cloneFn, pfx); exists {
		pt.sizeUpdate(is4, -1)
	}

	return pt
}

// Modify applies an insert, update, or delete operation for the value
// associated with the given prefix. The supplied callback decides the
// operation: it is called with the current value (or zero if not found)
// and a boolean indicating whether the prefix exists. The callback must
// return a new value and a delete flag: del == false inserts or updates,
// del == true deletes the entry if it exists (otherwise no-op).
//
// The callback is invoked at most once per call.
//
// The operation is determined by the callback function, which is called with:
//
//	val:   the current value (or zero value if not found)
//	found: true if the prefix currently exists, false otherwise
//
// The callback returns:
//
//	val: the new value to insert or update (ignored if del == true)
//	del: true to delete the entry, false to insert or update
//
// Summary of callback semantics:
//
//	| cb-input        | cb-return       | Ops    |
//	------------------------------------- --------
//	| (zero,   false) | (_,      true)  | no-op  |
//	| (zero,   false) | (newVal, false) | insert |
//	| (oldVal, true)  | (newVal, false) | update |
//	| (oldVal, true)  | (_,      true)  | delete |
//	------------------------------------- --------
func (t *liteTable[V]) Modify(pfx netip.Prefix, cb func(_ V, ok bool) (_ V, del bool)) {
	if !pfx.IsValid() {
		return
	}

	// canonicalize prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()

	n := t.rootNodeByVersion(is4)

	delta := n.Modify(pfx, cb)
	t.sizeUpdate(is4, delta)
}

// ModifyPersist is similar to Modify but the receiver isn't modified and
// a new *liteTable is returned.
func (t *liteTable[V]) ModifyPersist(pfx netip.Prefix, cb func(_ V, ok bool) (_ V, del bool)) *liteTable[V] {
	if !pfx.IsValid() {
		return t
	}

	// make a cheap test in front of expensive operation
	oldVal, ok := t.Get(pfx)
	val := oldVal

	// to clone or not to clone ...
	cloneFn := value.CloneFnFactory[V]()
	if cloneFn != nil && ok {
		val = cloneFn(oldVal)
	}

	newVal, del := cb(val, ok)

	switch {
	case !ok && del: // no-op
		return t

	case !ok && !del: // insert
		return t.InsertPersist(pfx, newVal)

	case ok && !del: // update
		return t.InsertPersist(pfx, newVal)

	case ok && del: // delete
		return t.DeletePersist(pfx)
	}

	panic("unreachable")
}

// Supernets returns an iterator over all supernet routes that cover the given prefix pfx.
//
// The traversal searches both exact-length and shorter (less specific) prefixes that
// include pfx. Starting from the most specific position in the trie,
// it walks upward through parent nodes and yields any matching entries found at each level.
//
// The iteration order is reverse-CIDR: from longest prefix match (LPM) towards
// least-specific routes.
//
// This can be used to enumerate all covering supernet routes in routing-based
// policy engines, diagnostics tools, or fallback resolution logic.
//
// Example:
//
//	for supernet, val := range table.Supernets(netip.MustParsePrefix("192.0.2.128/25")) {
//	    fmt.Println("Covered by:", supernet, "->", val)
//	}
//
// The iteration can be stopped early by breaking from the range loop.
// Returns an empty iterator if the prefix is invalid.
func (t *liteTable[V]) Supernets(pfx netip.Prefix) iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if !pfx.IsValid() {
			return
		}

		// canonicalize the prefix
		pfx = pfx.Masked()

		is4 := pfx.Addr().Is4()
		n := t.rootNodeByVersion(is4)

		n.Supernets(pfx, yield)
	}
}

// Subnets returns an iterator over all subnets of the given prefix
// in natural CIDR sort order. This includes prefixes of the same length
// (exact match) and longer (more specific) prefixes that are contained
// within the given prefix.
//
// Example:
//
//	for sub, val := range table.Subnets(netip.MustParsePrefix("10.0.0.0/8")) {
//	    fmt.Println("Covered:", sub, "->", val)
//	}
//
// The iteration can be stopped early by breaking from the range loop.
// Returns an empty iterator if the prefix is invalid.
func (t *liteTable[V]) Subnets(pfx netip.Prefix) iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if !pfx.IsValid() {
			return
		}

		pfx = pfx.Masked()
		is4 := pfx.Addr().Is4()

		n := t.rootNodeByVersion(is4)
		n.Subnets(pfx, yield)
	}
}

// OverlapsPrefix reports whether any prefix in the routing table overlaps with
// the given prefix. Two prefixes overlap if they share any IP addresses.
//
// The check is bidirectional: it returns true if the input prefix is covered by an existing
// route, or if any stored route is itself contained within the input prefix.
//
// Internally, the function normalizes the prefix and descends the relevant trie branch,
// using stride-based logic to identify overlap without performing a full lookup.
//
// This is useful for containment tests, route validation, or policy checks using prefix
// semantics without retrieving exact matches.
func (t *liteTable[V]) OverlapsPrefix(pfx netip.Prefix) bool {
	if !pfx.IsValid() {
		return false
	}

	// canonicalize the prefix
	pfx = pfx.Masked()

	is4 := pfx.Addr().Is4()
	n := t.rootNodeByVersion(is4)

	return n.OverlapsPrefixAtDepth(pfx, 0)
}

// Overlaps reports whether any route in the receiver table overlaps
// with a route in the other table, in either direction.
//
// The overlap check is bidirectional: it returns true if any IP prefix
// in the receiver is covered by the other table, or vice versa.
// This includes partial overlaps, exact matches, and supernet/subnet relationships.
//
// Both IPv4 and IPv6 route trees are compared independently. If either
// tree has overlapping routes, the function returns true.
//
// This is useful for conflict detection, policy enforcement,
// or validating mutually exclusive routing domains.
func (t *liteTable[V]) Overlaps(o *liteTable[V]) bool {
	return t.Overlaps4(o) || t.Overlaps6(o)
}

// Overlaps4 is like [liteTable.Overlaps] but for the v4 routing table only.
func (t *liteTable[V]) Overlaps4(o *liteTable[V]) bool {
	if t.size4 == 0 || o.size4 == 0 {
		return false
	}
	return t.root4.Overlaps(&o.root4, 0)
}

// Overlaps6 is like [liteTable.Overlaps] but for the v6 routing table only.
func (t *liteTable[V]) Overlaps6(o *liteTable[V]) bool {
	if t.size6 == 0 || o.size6 == 0 {
		return false
	}
	return t.root6.Overlaps(&o.root6, 0)
}

// Union merges another routing table into the receiver table, modifying it in-place.
//
// All prefixes and values from the other table (o) are inserted into the receiver.
// If a duplicate prefix exists in both tables, the value from o replaces the existing entry.
// This duplicate is shallow-copied by default, but if the value type V implements the
// Clone method, the value is deeply cloned before insertion. See also liteTable.Clone.
func (t *liteTable[V]) Union(o *liteTable[V]) {
	// panics on nil receiver
	_ = t.size4

	// panics on nil argument
	if o.size4 == 0 && o.size6 == 0 {
		return
	}
	// t is unchanged
	if o == t {
		return
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	dup4 := t.root4.UnionRec(cloneFn, &o.root4, 0)
	dup6 := t.root6.UnionRec(cloneFn, &o.root6, 0)

	t.size4 += o.size4 - dup4
	t.size6 += o.size6 - dup6
}

// UnionPersist is similar to [Union] but the receiver isn't modified.
//
// All nodes touched during union are cloned and a new *liteTable is returned.
// If o is empty, no nodes are touched and the receiver may be
// returned unchanged.
func (t *liteTable[V]) UnionPersist(o *liteTable[V]) *liteTable[V] {
	// panics on nil receiver
	_ = t.size4

	// panics on nil argument
	if o.size4 == 0 && o.size6 == 0 {
		return t
	}
	if o == t {
		return t
	}

	// Create a cloning function for deep copying values;
	// returns nil if V does not provide a Clone() V method.
	cloneFn := value.CloneFnFactory[V]()

	// new liteTable with root nodes just copied.
	pt := &liteTable[V]{
		root4: t.root4,
		root6: t.root6,
		//
		size4: t.size4,
		size6: t.size6,
	}

	// only clone the root node if there is something to union
	if o.size4 != 0 {
		pt.root4 = *t.root4.CloneFlat(cloneFn)
	}
	if o.size6 != 0 {
		pt.root6 = *t.root6.CloneFlat(cloneFn)
	}

	dup4 := pt.root4.UnionRecPersist(cloneFn, &o.root4, 0)
	dup6 := pt.root6.UnionRecPersist(cloneFn, &o.root6, 0)

	pt.size4 += o.size4 - dup4
	pt.size6 += o.size6 - dup6

	return pt
}

// Equal checks whether two tables are structurally and semantically equal.
// It ensures both trees (IPv4-based and IPv6-based) have the same sizes and
// recursively compares their root nodes.
//
// If V implements an `Equal(V) bool` method, its custom equality logic is used.
// Otherwise, values are compared directly using the == operator.
//
// Note: If V implements `Equal(V) bool` with a pointer receiver, the Equal
// method should handle nil receivers gracefully.
//
// ATTENTION: If V is not comparable at runtime (such as a slice or map without an `Equal`
// method), a runtime panic will occur.
func (t *liteTable[V]) Equal(o *liteTable[V]) bool {
	if t.size4 != o.size4 || t.size6 != o.size6 {
		return false
	}
	if o == t {
		return true
	}

	return t.root4.EqualRec(&o.root4) && t.root6.EqualRec(&o.root6)
}

// Clone returns a copy of the routing table.
// The payload of type V is shallow copied by default. To enable deep copying,
// implement the following method on your value type:
//
//	Clone() V
//
// Example:
//
//	type MyValue struct { Data []byte }
//	func (v MyValue) Clone() MyValue {
//	    return MyValue{Data: slices.Clone(v.Data)}
//	}
//
// The bart package will automatically detect and use this method via Go's
// structural typing.
//
// Note: If V implements Clone() V with a pointer receiver, the Clone
// method should handle nil receivers gracefully.
func (t *liteTable[V]) Clone() *liteTable[V] {
	c := new(liteTable[V])

	cloneFn := value.CloneFnFactory[V]()

	c.root4 = *t.root4.CloneRec(cloneFn)
	c.root6 = *t.root6.CloneRec(cloneFn)

	c.size4 = t.size4
	c.size6 = t.size6

	return c
}

// Size returns the prefix count.
func (t *liteTable[V]) Size() int {
	return t.size4 + t.size6
}

// Size4 returns the IPv4 prefix count.
func (t *liteTable[V]) Size4() int {
	return t.size4
}

// Size6 returns the IPv6 prefix count.
func (t *liteTable[V]) Size6() int {
	return t.size6
}

// All returns an iterator over all prefix–value pairs in the table.
//
// The iteration order is unspecified and may vary between calls; for a stable order,
// use [liteTable.AllSorted].
//
// IMPORTANT: Modifying the table during iteration is not allowed,
// as this would interfere with the internal traversal and may corrupt or
// prematurely terminate the iteration.
func (t *liteTable[V]) All() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		_ = t.root4.AllRec(stridePath{}, 0, true, yield) && t.root6.AllRec(stridePath{}, 0, false, yield)
	}
}

// All4 is like [liteTable.All] but only for the v4 routing table.
func (t *liteTable[V]) All4() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		_ = t.root4.AllRec(stridePath{}, 0, true, yield)
	}
}

// All6 is like [liteTable.All] but only for the v6 routing table.
func (t *liteTable[V]) All6() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		_ = t.root6.AllRec(stridePath{}, 0, false, yield)
	}
}

// AllSorted is like [liteTable.All] but the iteration is ordered in canonical
// CIDR prefix sort order.
func (t *liteTable[V]) AllSorted() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		_ = t.root4.AllRecSorted(stridePath{}, 0, true, yield) &&
			t.root6.AllRecSorted(stridePath{}, 0, false, yield)
	}
}

// AllSorted4 is like [liteTable.AllSorted] but only for the v4 routing table.
func (t *liteTable[V]) AllSorted4() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		_ = t.root4.AllRecSorted(stridePath{}, 0, true, yield)
	}
}

// AllSorted6 is like [liteTable.AllSorted] but only for the v6 routing table.
func (t *liteTable[V]) AllSorted6() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		_ = t.root6.AllRecSorted(stridePath{}, 0, false, yield)
	}
}

// Fprint writes a hierarchical tree diagram of the ordered CIDRs
// with default formatted payload V to w.
//
// The order from top to bottom is in ascending order of the prefix address
// and the subtree structure is determined by the CIDRs coverage.
//
//	▼
//	├─ 10.0.0.0/8 (V)
//	│  ├─ 10.0.0.0/24 (V)
//	│  └─ 10.0.1.0/24 (V)
//	├─ 127.0.0.0/8 (V)
//	│  └─ 127.0.0.1/32 (V)
//	├─ 169.254.0.0/16 (V)
//	├─ 172.16.0.0/12 (V)
//	└─ 192.168.0.0/16 (V)
//	   └─ 192.168.1.0/24 (V)
//	▼
//	└─ ::/0 (V)
//	   ├─ ::1/128 (V)
//	   ├─ 2000::/3 (V)
//	   │  └─ 2001:db8::/32 (V)
//	   └─ fe80::/10 (V)
func (t *liteTable[V]) Fprint(w io.Writer) error {
	if w == nil && t != nil {
		return fmt.Errorf("nil writer")
	}

	// v4
	if err := t.fprint(w, true); err != nil {
		return err
	}

	// v6
	if err := t.fprint(w, false); err != nil {
		return err
	}

	return nil
}

// fprint is the version dependent adapter to fprintRec.
func (t *liteTable[V]) fprint(w io.Writer, is4 bool) error {
	n := t.rootNodeByVersion(is4)
	if n.IsEmpty() {
		return nil
	}

	if _, err := fmt.Fprint(w, "▼\n"); err != nil {
		return err
	}

	startParent := nodes.TrieItem[V]{
		Node: nil,
		Idx:  0,
		Path: stridePath{},
		Is4:  is4,
	}

	return n.FprintRec(w, startParent, "")
}

// MarshalText implements the [encoding.TextMarshaler] interface,
// just a wrapper for [liteTable.Fprint].
func (t *liteTable[V]) MarshalText() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := t.Fprint(w); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// MarshalJSON dumps the table into two sorted lists: for ipv4 and ipv6.
// Every root and subnet is an array, not a map, because the order matters.
func (t *liteTable[V]) MarshalJSON() ([]byte, error) {
	result := struct {
		Ipv4 []DumpListNode[V] `json:"ipv4,omitempty"`
		Ipv6 []DumpListNode[V] `json:"ipv6,omitempty"`
	}{
		Ipv4: t.DumpList4(),
		Ipv6: t.DumpList6(),
	}

	buf, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// DumpList4 dumps the ipv4 tree into a list of roots and their subnets.
// It can be used to analyze the tree or build the text or JSON serialization.
func (t *liteTable[V]) DumpList4() []DumpListNode[V] {
	return t.dumpListRec(&t.root4, 0, stridePath{}, 0, true)
}

// DumpList6 dumps the ipv6 tree into a list of roots and their subnets.
// It can be used to analyze the tree or build custom JSON representation.
func (t *liteTable[V]) DumpList6() []DumpListNode[V] {
	return t.dumpListRec(&t.root6, 0, stridePath{}, 0, false)
}

// dumpListRec, build the data structure rec-descent with the help of directItemsRec.
// anyNode is nodes.BartNode, nodes.FastNode or nodes.LiteNode
func (t *liteTable[V]) dumpListRec(anyNode any, parentIdx uint8, path stridePath, depth int, is4 bool) []DumpListNode[V] {
	// recursion stop condition
	if anyNode == nil {
		return nil
	}

	// the same method is generated for all table types, therefore
	// type assert to the smallest needed interface.
	// The panic on wrong type assertion is by intention, MUST NOT happen
	n := anyNode.(interface {
		DirectItemsRec(uint8, stridePath, int, bool) []nodes.TrieItem[V]
	})

	directItems := n.DirectItemsRec(parentIdx, path, depth, is4)

	// sort the items by prefix
	slices.SortFunc(directItems, func(a, b nodes.TrieItem[V]) int {
		return nodes.CmpPrefix(a.Cidr, b.Cidr)
	})

	dumpNodes := make([]DumpListNode[V], 0, len(directItems))

	for _, item := range directItems {
		dumpNodes = append(dumpNodes, DumpListNode[V]{
			CIDR:  item.Cidr,
			Value: item.Val,
			// build it rec-descent, item.Node is also from type any
			Subnets: t.dumpListRec(item.Node, item.Idx, item.Path, item.Depth, is4),
		})
	}

	return dumpNodes
}

// dumpString is just a wrapper for dump.
func (t *liteTable[V]) dumpString() string {
	w := new(strings.Builder)
	t.dump(w)

	return w.String()
}

// dump the table structure and all the nodes to w.
func (t *liteTable[V]) dump(w io.Writer) {
	if t.size4 > 0 {
		stats := t.root4.StatsRec()
		fmt.Fprintln(w)
		fmt.Fprintf(w, "### IPv4: size(%d), subnodes(%d), prefixes(%d), leaves(%d), fringes(%d)",
			t.size4, stats.SubNodes, stats.Prefixes, stats.Leaves, stats.Fringes)

		t.root4.DumpRec(w, stridePath{}, 0, true)
	}

	if t.size6 > 0 {
		stats := t.root6.StatsRec()
		fmt.Fprintln(w)
		fmt.Fprintf(w, "### IPv6: size(%d), subnodes(%d), prefixes(%d), leaves(%d), fringes(%d)",
			t.size6, stats.SubNodes, stats.Prefixes, stats.Leaves, stats.Fringes)

		t.root6.DumpRec(w, stridePath{}, 0, false)
	}
}
