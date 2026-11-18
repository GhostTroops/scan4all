// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"github.com/gaissmai/bart/internal/sparse"
)

// FastNode is based on [BartNode], but it also uses a cache ([256]uint8)
// per node to speed up traversal of the multi-bit trie.
// Lookups become faster, but this requires more memory per prefix,
// and updates (insertions/deletions) also become slower due to the
// overhead of managing the cache.
type FastNode[V any] struct {
	Prefixes sparse.Array256[V]
	Children sparse.Array256[any]
	// map addr to slice idx (aka rank)
	childRankCache [256]uint8
}

// InsertChild adds a child node at the specified address (0-255).
// The child can be a *FastNode[V], *LeafNode[V], or *FringeNode[V].
// Returns true if a child already existed at that address.
func (n *FastNode[V]) InsertChild(addr uint8, child any) (exists bool) {
	var rank0 int
	rank0, exists = n.Children.InsertAt(addr, child)
	if exists {
		// Update only: the value at addr is overwritten in-place by InsertAt.
		// childRankCache[addr] is not refreshed because the rank is unchanged
		// the position of addr in the sparse slice does not shift on an update.
		return
	}

	// new child inserted? cache the rank value for this addr
	//nolint:gosec // G115: integer overflow conversion int -> uint8
	n.childRankCache[addr] = uint8(rank0)

	// increment all cached ranks after addr
	for i := 255; i > int(addr); i-- {
		n.childRankCache[i]++
	}
	return
}

// DeleteChild removes the child node at the specified address.
// This operation is idempotent - removing a non-existent child is safe.
func (n *FastNode[V]) DeleteChild(addr uint8) (exists bool) {
	_, exists = n.Children.DeleteAt(addr)

	// nothing deleted
	if !exists {
		return exists
	}

	// decrement all cached ranks after addr
	for i := 255; i > int(addr); i-- {
		n.childRankCache[i]--
	}

	return exists
}

// GetChild retrieves the child node at the specified address.
// Returns the child and true if found, or nil and false if not present.
func (n *FastNode[V]) GetChild(addr uint8) (any, bool) {
	if n.Children.Test(addr) {
		rank0 := n.childRankCache[addr]
		return n.Children.Items[rank0], true
	}
	return nil, false
}

// MustGetChild retrieves the child at addr using the pre-cached rank stored in
// childRankCache[addr] for a direct O(1) array access without an existence check.
//
// The caller must guarantee that addr is present (Children.Test(addr) == true).
// If addr is absent, childRankCache[addr] contains the number of occupied
// addresses less than addr (maintained by InsertChild/DeleteChild), so the
// behaviour is undefined: either a wrong child is returned silently, or the
// call panics with an index-out-of-range error.
func (n *FastNode[V]) MustGetChild(addr uint8) any {
	rank0 := n.childRankCache[addr]
	return n.Children.Items[rank0]
}

// CloneFlat returns a shallow copy of the current node, optionally performing deep copies of values.
//
// If cloneFn is nil, the stored values in prefixes are copied directly without modification.
// Otherwise, cloneFn is applied to each stored value for deep cloning.
// Child nodes are cloned shallowly: LeafNode and FringeNode children are cloned via their clone methods,
// but child nodes of type *FastNode[V] (subnodes) are assigned as-is without recursive cloning.
// This method does not recursively clone descendants beyond the immediate children.
//
// Note: The returned node is a new instance with copied slices but only shallow copies of nested nodes,
// except for LeafNode and FringeNode children which are cloned according to cloneFn.
func (n *FastNode[V]) CloneFlat(cloneFn func(V) V) *FastNode[V] {
	if n == nil {
		return nil
	}

	c := new(FastNode[V])

	// copy ...
	c.Prefixes = *(n.Prefixes.Copy())

	// ... and clone the values
	if cloneFn != nil {
		for i, v := range c.Prefixes.Items {
			c.Prefixes.Items[i] = cloneFn(v)
		}
	}

	// copy ...
	c.childRankCache = n.childRankCache
	c.Children = *(n.Children.Copy())

	// Iterate over children to flat clone leaf/fringe nodes;
	// for *FastNode[V] children, keep shallow references (no recursive clone)
	for i, anyKid := range c.Children.Items {
		switch kid := anyKid.(type) {
		case *FastNode[V]:
			// Shallow copy
		case *LeafNode[V]:
			// Clone leaf nodes, applying cloneFn as needed
			c.Children.Items[i] = kid.CloneLeaf(cloneFn)
		case *FringeNode[V]:
			// Clone fringe nodes, applying cloneFn as needed
			c.Children.Items[i] = kid.CloneFringe(cloneFn)
		default:
			panic("logic error, wrong node type")
		}
	}

	return c
}
