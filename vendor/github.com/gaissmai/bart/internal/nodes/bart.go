// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"github.com/gaissmai/bart/internal/sparse"
)

// BartNode represents a single trie level in the multibit routing table.
//
// Unlike the original ART algorithm, this implementation uses popcount-compressed
// sparse arrays instead of fixed-size allocations. Insertions and lookups rely on
// fast bitset operations and precomputed lookup tables to maximize CPU pipelining
// and cache efficiency.
//
// Each BartNode maintains two distinct sparse arrays:
//
//  1. Prefixes: Stores routing entries (prefix -> value) for the current stride.
//     These are laid out as a complete binary tree using the baseIndex()
//     function mapping from the ART algorithm. Prefixes that match exactly at
//     the maximum trie depth are always stored here.
//
//  2. Children: Holds pointers to the next logical levels with a branching
//     factor of 256 (8 bits per stride).
//
// A slot in the Children array may contain one of three types:
//   - *BartNode[V]:   An internal intermediate node for further trie traversal.
//   - *FringeNode[V]: A path-compressed node if it qualifies as fringe [IsFringe]
//   - *LeafNode[V]:   A path-compressed node otherwise.
//
// Note: LeafNode and FringeNode are created through path compression and
// are automatically split into regular BartNodes when a more specific prefix
// is inserted that requires further branching.
type BartNode[V any] struct {
	Prefixes sparse.Array256[V]
	Children sparse.Array256[any]
}

// InsertChild adds a child node at the specified address (0-255).
// The child can be a *BartNode[V], *LeafNode[V], or *FringeNode[V].
// Returns true if a child already existed at that address.
func (n *BartNode[V]) InsertChild(addr uint8, child any) (exists bool) {
	_, exists = n.Children.InsertAt(addr, child)
	return
}

// GetChild retrieves the child node at the specified address.
// Returns the child and true if found, or nil and false if not present.
func (n *BartNode[V]) GetChild(addr uint8) (any, bool) {
	return n.Children.Get(addr)
}

// MustGetChild retrieves the child at the specified address, panicking if not found.
// This method should only be used when the caller is certain the child exists.
func (n *BartNode[V]) MustGetChild(addr uint8) any {
	return n.Children.MustGet(addr)
}

// DeleteChild removes the child node at the specified address.
// This operation is idempotent - removing a non-existent child is safe.
func (n *BartNode[V]) DeleteChild(addr uint8) (exists bool) {
	_, exists = n.Children.DeleteAt(addr)
	return exists
}

// CloneFlat returns a shallow copy of the current node, optionally performing deep copies of values.
//
// If cloneFn is nil, the stored values in prefixes are copied directly without modification.
// Otherwise, cloneFn is applied to each stored value for deep cloning.
// Child nodes are cloned shallowly: LeafNode and FringeNode children are cloned via their clone methods,
// but child nodes of type *BartNode[V] (subnodes) are assigned as-is without recursive cloning.
// This method does not recursively clone descendants beyond the immediate children.
//
// Note: The returned node is a new instance with copied slices but only shallow copies of nested nodes,
// except for LeafNode and FringeNode children which are cloned according to cloneFn.
func (n *BartNode[V]) CloneFlat(cloneFn func(V) V) *BartNode[V] {
	if n == nil {
		return nil
	}

	c := new(BartNode[V])

	// copy ...
	c.Prefixes = *(n.Prefixes.Copy())

	// ... and clone the values
	if cloneFn != nil {
		for i, v := range c.Prefixes.Items {
			c.Prefixes.Items[i] = cloneFn(v)
		}
	}

	// copy ...
	c.Children = *(n.Children.Copy())

	// Iterate over children to flat clone leaf/fringe nodes;
	// for *BartNode[V] children, keep shallow references (no recursive clone)
	for i, anyKid := range c.Children.Items {
		switch kid := anyKid.(type) {
		case *BartNode[V]:
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
