// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package bart

import (
	"io"
	"iter"
	"net/netip"
)

// Lite follows the BART design but with no payload.
// It is ideal for simple IP ACLs (access-control-lists) with plain
// true/false results with the smallest memory consumption.
//
// The zero value is ready to use.
//
// A Lite table must not be copied by value; always pass by pointer.
// Nil pointers as receivers or arguments are forbidden and will panic.
//
// Performance note: Do not pass IPv4-in-IPv6 addresses (e.g., ::ffff:192.0.2.1)
// as input. The methods do not perform automatic unmapping to avoid unnecessary
// overhead for the common case where native addresses are used.
// Users should unmap IPv4-in-IPv6 addresses to their native IPv4 form
// (e.g., 192.0.2.1) before calling these methods.
type Lite struct {
	liteTable[struct{}]
}

// Get performs an exact-prefix lookup and returns whether the exact
// prefix exists. The prefix is canonicalized (Masked) before lookup.
//
// This is an exact-match operation (no LPM). The prefix must match exactly
// in both address and prefix length to be found.
// If pfx is valid and exists, true is returned, otherwise false.
//
// For longest-prefix-match (LPM) lookups, use Contains(ip), Lookup(ip),
// LookupPrefix(pfx) or LookupPrefixLPM(pfx) instead.
func (l *Lite) Get(pfx netip.Prefix) bool {
	_, ok := l.liteTable.Get(pfx)
	return ok
}

// Lookup performs a longest-prefix-match (LPM) for addr.
//
// Note: Lite stores no payload values, so this method is rarely useful.
// Prefer Contains(addr) to check whether any prefix matches the address.
// For exact prefix existence use Get(pfx). For prefix-based LPM use
// LookupPrefix or LookupPrefixLPM.
//
// Returns true if any prefix matches ip, otherwise false.
func (l *Lite) Lookup(ip netip.Addr) bool {
	return l.Contains(ip)
}

// LookupPrefix performs a longest prefix match lookup for any address within
// the given prefix.
//
// Returns true if a matching prefix is found, otherwise false.
func (l *Lite) LookupPrefix(pfx netip.Prefix) bool {
	_, _, ok := l.lookupPrefixLPM(pfx, false)
	return ok
}

// LookupPrefixLPM performs a longest prefix match lookup for any address within
// the given prefix. It finds the most specific routing table entry that would
// match any address in the provided prefix range.
//
// This is functionally identical to LookupPrefix but returns the
// matching LPM prefix itself.
//
// This method is slower than LookupPrefix and should only be used if the
// matching lpm entry is also required for other reasons.
//
// Returns the matching prefix and true if found, otherwise the zero value and false.
func (l *Lite) LookupPrefixLPM(pfx netip.Prefix) (lpmPfx netip.Prefix, ok bool) {
	lpmPfx, _, ok = l.lookupPrefixLPM(pfx, true)
	return
}

// Insert adds a prefix to the routing table.
// If the prefix already exists, it's a no-op; otherwise a new entry is created.
// Invalid prefixes are silently ignored.
//
// The prefix is automatically canonicalized using pfx.Masked() to ensure
// consistent behavior regardless of host bits in the input.
func (l *Lite) Insert(pfx netip.Prefix) {
	l.liteTable.Insert(pfx, struct{}{})
}

// InsertPersist is similar to Insert but the receiver isn't modified.
//
// All nodes touched during insert are cloned and a new *Lite is returned.
// This is not a full [Lite.Clone], all untouched nodes are still referenced
// from both Tables.
//
// This is orders of magnitude slower than Insert,
// typically taking μsec instead of nsec.
//
// The bulk table load could be done with [Lite.Insert] and then you can
// use [Lite.InsertPersist], [Lite.ModifyPersist] and [Lite.DeletePersist]
// for further lock-free ops.
func (l *Lite) InsertPersist(pfx netip.Prefix) *Lite {
	lp := l.liteTable.InsertPersist(pfx, struct{}{})
	if lp == &l.liteTable {
		// pfx is invalid or didn't exist
		return l
	}
	//nolint:govet // copy of *lp is here by intention
	return &Lite{*lp}
}

// DeletePersist is similar to Delete but does not modify the receiver.
//
// It performs a copy-on-write delete operation, cloning all nodes
// touched during deletion and returning a new *Lite reflecting the change.
//
// If the prefix is invalid or doesn't exist, the original table is
// returned unchanged.
//
// Due to cloning overhead this is significantly slower than Delete,
// typically taking μsec instead of nsec.
func (l *Lite) DeletePersist(pfx netip.Prefix) *Lite {
	lp := l.liteTable.DeletePersist(pfx)
	if lp == &l.liteTable {
		// pfx is invalid or didn't exist
		return l
	}

	//nolint:govet // copy of *lp is here by intention
	return &Lite{*lp}
}

// Modify applies an insert, update, or delete for the given prefix.
// The prefix is canonicalized (Masked) internally before the operation.
// The operation is determined by the callback function, which is called with:
//
//	true:  the prefix is in table
//	false: the prefix is not in table
//
// The callback returns:
//
//	true:  delete the entry
//	false: insert or update
//
// Summary of callback semantics:
//
//	| input | return | op     |
//	---------------------------
//	| false | true   | no-op  |
//	| false | false  | insert |
//	| true  | false  | update |
//	| true  | true   | delete |
//	---------------------------
func (l *Lite) Modify(pfx netip.Prefix, cb func(exists bool) (del bool)) {
	// Adapt the callback to work with liteTable's signature
	adaptedCb := func(_ struct{}, exists bool) (_ struct{}, del bool) {
		return struct{}{}, cb(exists)
	}

	l.liteTable.Modify(pfx, adaptedCb)
}

// ModifyPersist is similar to Modify but the receiver isn't modified and
// a new *Lite is returned.
func (l *Lite) ModifyPersist(pfx netip.Prefix, cb func(exists bool) (del bool)) *Lite {
	// wrap callback to match the signature of liteTable.ModifyPersist
	cbWrapper := func(_ struct{}, exists bool) (_ struct{}, del bool) {
		return struct{}{}, cb(exists)
	}

	lp := l.liteTable.ModifyPersist(pfx, cbWrapper)
	if lp == &l.liteTable {
		// pfx is invalid or didn't exist
		return l
	}

	//nolint:govet // copy of *lp is here by intention
	return &Lite{*lp}
}

// dropSeq2 converts a Seq2[netip.Prefix, V] into a Seq[netip.Prefix] by discarding the value.
func dropSeq2[V any](seq2 iter.Seq2[netip.Prefix, V]) iter.Seq[netip.Prefix] {
	return func(yield func(netip.Prefix) bool) {
		seq2(func(p netip.Prefix, _ V) bool {
			return yield(p)
		})
	}
}

// Aggregate compresses the Lite table in-place by merging overlapping
// and adjacent IP prefixes into their minimal covering CIDR blocks.
//
// When the Lite table is used as an Access Control List (ACL), aggregation
// preserves identical access permissions while reducing memory footprint
// via two mechanisms:
//  1. Overlapping: More specific subnets fully contained within a broader
//     supernet (e.g., 10.1.0.0/16 inside 10.0.0.0/8) are redundant and removed.
//  2. Adjacent: Sibling prefixes of equal length that completely cover their
//     common parent (e.g., 192.168.0.0/25 and 192.168.0.128/25) are combined
//     into a single supernet (192.168.0.0/24).
func (l *Lite) Aggregate() {
	l.liteTable.Aggregate()
}

// Clone returns a copy of the routing table.
func (l *Lite) Clone() *Lite {
	return &Lite{*l.liteTable.Clone()}
}

// Union merges another routing table into the receiver table, modifying it in-place.
//
// All prefixes from the other table (o) are inserted into the receiver.
func (l *Lite) Union(o *Lite) {
	l.liteTable.Union(&o.liteTable)
}

// UnionPersist is similar to [Union] but the receiver isn't modified.
//
// All nodes touched during union are cloned and a new *Lite is returned.
// If o is empty, no nodes are touched and the receiver may be
// returned unchanged.
func (l *Lite) UnionPersist(o *Lite) *Lite {
	lp := l.liteTable.UnionPersist(&o.liteTable)
	if lp == &l.liteTable {
		return l
	}
	//nolint:govet // copy of *lp is here by intention
	return &Lite{*lp}
}

// All returns an iterator over all prefixes in the table.
//
// The iteration order is unspecified and may vary between calls; for a stable order,
// use [Lite.AllSorted].
//
// IMPORTANT: Modifying the table during iteration is not allowed,
// as this would interfere with the internal traversal and may corrupt or
// prematurely terminate the iteration.
func (l *Lite) All() iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.All())
}

// All4 is like [Lite.All] but only for the v4 routing table.
func (l *Lite) All4() iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.All4())
}

// All6 is like [Lite.All] but only for the v6 routing table.
func (l *Lite) All6() iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.All6())
}

// AllSorted is like [Lite.All] but the iteration is ordered in canonical
// CIDR prefix sort order.
func (l *Lite) AllSorted() iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.AllSorted())
}

// AllSorted4 is like [Lite.AllSorted] but only for the v4 routing table.
func (l *Lite) AllSorted4() iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.AllSorted4())
}

// AllSorted6 is like [Lite.AllSorted] but only for the v6 routing table.
func (l *Lite) AllSorted6() iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.AllSorted6())
}

// Subnets returns an iterator over all subnets of the given prefix
// in natural CIDR sort order. This includes prefixes of the same length
// (exact match) and longer (more specific) prefixes that are contained
// within the given prefix.
//
// Example:
//
//	for sub := range table.Subnets(netip.MustParsePrefix("10.0.0.0/8")) {
//	    fmt.Println("Covered:", sub)
//	}
//
// The iteration can be stopped early by breaking from the range loop.
// Returns an empty iterator if the prefix is invalid.
func (l *Lite) Subnets(pfx netip.Prefix) iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.Subnets(pfx))
}

// Supernets returns an iterator over all supernet routes that cover the given prefix pfx.
//
// The traversal searches both exact-length and shorter (less specific) prefixes that
// overlap or include pfx. Starting from the most specific position in the trie,
// it walks upward through parent nodes and yields any matching entries found at each level.
//
// The iteration order is reverse-CIDR: from longest prefix match (LPM) towards
// least-specific routes.
//
// The search is protocol-specific (IPv4 or IPv6) and stops immediately if the yield
// function returns false. If pfx is invalid, the function silently returns.
//
// This can be used to enumerate all covering supernet routes in routing-based
// policy engines, diagnostics tools, or fallback resolution logic.
//
// Example:
//
//	for supernet := range table.Supernets(netip.MustParsePrefix("192.0.2.128/25")) {
//	    fmt.Println("Matched covering route:", supernet)
//	}
func (l *Lite) Supernets(pfx netip.Prefix) iter.Seq[netip.Prefix] {
	return dropSeq2(l.liteTable.Supernets(pfx))
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
//
// It is intentionally not nil-receiver safe: calling with a nil
// receiver will panic by design.
func (l *Lite) Overlaps(o *Lite) bool {
	return l.liteTable.Overlaps(&o.liteTable)
}

// Overlaps4 is like [Lite.Overlaps] but for the v4 routing table only.
func (l *Lite) Overlaps4(o *Lite) bool {
	return l.liteTable.Overlaps4(&o.liteTable)
}

// Overlaps6 is like [Lite.Overlaps] but for the v6 routing table only.
func (l *Lite) Overlaps6(o *Lite) bool {
	return l.liteTable.Overlaps6(&o.liteTable)
}

// Equal checks whether two tables are structurally and semantically equal.
// It ensures both trees (IPv4-based and IPv6-based) have the same sizes and
// recursively compares their root nodes.
//
// Note: Lite has no payload values, so this only checks structural equality.
func (l *Lite) Equal(o *Lite) bool {
	return l.liteTable.Equal(&o.liteTable)
}

// DumpList4 dumps the ipv4 tree into a list of roots and their subnets.
// It can be used to analyze the tree or build the text or JSON serialization.
func (l *Lite) DumpList4() []DumpListNode[struct{}] {
	return l.liteTable.DumpList4()
}

// DumpList6 dumps the ipv6 tree into a list of roots and their subnets.
// It can be used to analyze the tree or build custom JSON representation.
func (l *Lite) DumpList6() []DumpListNode[struct{}] {
	return l.liteTable.DumpList6()
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
func (l *Lite) Fprint(w io.Writer) error {
	return l.liteTable.Fprint(w)
}

// MarshalJSON dumps the table into two sorted lists: for ipv4 and ipv6.
// Every root and subnet is an array, not a map, because the order matters.
func (l *Lite) MarshalJSON() ([]byte, error) {
	return l.liteTable.MarshalJSON()
}

// MarshalText implements the [encoding.TextMarshaler] interface,
// just a wrapper for [liteTable.Fprint].
func (l *Lite) MarshalText() ([]byte, error) {
	return l.liteTable.MarshalText()
}
