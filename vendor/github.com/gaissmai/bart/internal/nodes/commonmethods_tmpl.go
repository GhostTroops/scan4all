//go:build generate

// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

//go:generate ../../scripts/generate-node-methods.sh

package nodes

// ### GENERATE DELETE START ###

// stub code for generator types and methods
// useful for gopls during development, deleted during go generate

import (
	"fmt"
	"io"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/gaissmai/bart/internal/allot"
	"github.com/gaissmai/bart/internal/art"
	"github.com/gaissmai/bart/internal/bitset"
	"github.com/gaissmai/bart/internal/lpm"
	"github.com/gaissmai/bart/internal/value"
)

type _NODE_TYPE[V any] struct {
	Prefixes struct{ bitset.BitSet256 }
	Children struct{ bitset.BitSet256 }
}

func (n *_NODE_TYPE[V]) PrefixCount() (_ int)                   { return }
func (n *_NODE_TYPE[V]) ChildCount() (_ int)                    { return }
func (n *_NODE_TYPE[V]) GetChild(uint8) (_ any, _ bool)         { return }
func (n *_NODE_TYPE[V]) MustGetChild(uint8) (_ any)             { return }
func (n *_NODE_TYPE[V]) InsertChild(uint8, any) (_ bool)        { return }
func (n *_NODE_TYPE[V]) DeleteChild(uint8) (_ bool)             { return }
func (n *_NODE_TYPE[V]) CloneRec(func(V) V) (_ *_NODE_TYPE[V])  { return }
func (n *_NODE_TYPE[V]) CloneFlat(func(V) V) (_ *_NODE_TYPE[V]) { return }

// ### GENERATE DELETE END ###

// IsEmpty returns true if the node contains no routing entries (prefixes)
// and no child nodes. Empty nodes are candidates for compression or removal
// during trie optimization.
func (n *_NODE_TYPE[V]) IsEmpty() bool {
	if n == nil {
		return true
	}
	return n.PrefixCount() == 0 && n.ChildCount() == 0
}

// ChildCount returns the number of slots used in this node.
func (n *_NODE_TYPE[V]) ChildCount() int {
	return n.Children.Len()
}

// ### GENERATE SKIP_LITE START ###

// PrefixCount returns the number of prefixes stored in this node.
func (n *_NODE_TYPE[V]) PrefixCount() int {
	return n.Prefixes.Len()
}

// GetPrefix retrieves the value associated with the prefix at the given index.
// Returns the value and true if found, or zero value and false if not present.
func (n *_NODE_TYPE[V]) GetPrefix(idx uint8) (val V, exists bool) {
	return n.Prefixes.Get(idx)
}

// MustGetPrefix retrieves the value at the specified index, panicking if not found.
// This method should only be used when the caller is certain the index exists.
func (n *_NODE_TYPE[V]) MustGetPrefix(idx uint8) (val V) {
	return n.Prefixes.MustGet(idx)
}

// InsertPrefix adds or updates a routing entry at the specified index with the given value.
// It returns true if a prefix already existed at that index (indicating an update),
// false if this is a new insertion.
func (n *_NODE_TYPE[V]) InsertPrefix(idx uint8, val V) (exists bool) {
	_, exists = n.Prefixes.InsertAt(idx, val)
	return
}

// DeletePrefix removes the prefix at the specified index.
// Returns true if the prefix existed, otherwise false.
func (n *_NODE_TYPE[V]) DeletePrefix(idx uint8) (exists bool) {
	_, exists = n.Prefixes.DeleteAt(idx)
	return exists
}

// AllIndices returns an iterator over all prefix entries.
// Each iteration yields the prefix index (uint8) and its associated value (V).
func (n *_NODE_TYPE[V]) AllIndices() iter.Seq2[uint8, V] {
	return func(yield func(uint8, V) bool) {
		for i, idx := range n.Prefixes.AllEnumerate() {
			if !yield(idx, n.Prefixes.Items[i]) {
				return
			}
		}
	}
}

// ### GENERATE SKIP_LITE END ###

// AllChildren returns an iterator over all child nodes.
// Each iteration yields the child's address (uint8) and the child node (any).
func (n *_NODE_TYPE[V]) AllChildren() iter.Seq2[uint8, any] {
	return func(yield func(addr uint8, child any) bool) {
		for i, addr := range n.Children.AllEnumerate() {
			if !yield(addr, n.Children.Items[i]) {
				return
			}
		}
	}
}

// Insert adds or updates a network prefix and its associated value in the trie.
// Traversal begins at the specified byte depth.
//
// The trie utilizes path compression to conserve memory. A prefix is inserted:
//   - Uncompressed into a node's prefix table at depth == strideCount.
//   - As a path-compressed FringeNode if it qualifies as fringe [IsFringe].
//   - As a path-compressed LeafNode otherwise.
//
// When a new prefix collides with an existing compressed node (Leaf or Fringe),
// Insert resolves the collision by creating a new intermediate node, pushing
// the existing entry down to the next level, and continuing traversal.
//
// Parameters:
//   - pfx: The network prefix to insert (must be in canonical/masked form).
//   - val: The value to associate with the prefix.
//   - depth: The current depth in the trie (0-based byte index).
//
// Returns true if an existing prefix was updated, false if a new insertion occurred.
func (n *_NODE_TYPE[V]) Insert(pfx netip.Prefix, val V, depth int) (exists bool) {
	ip := pfx.Addr() // the pfx must be in canonical form
	pfxLen := pfx.Bits()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// Traverse the prefix's octets. Each depth corresponds to an 8-bit stride.
	// We descend through the trie until we either reach the final stride (depth == strideCount)
	// or find an empty child slot where we can path-compress the remaining strides.
	for ; depth < len(octets); depth++ {
		octet := octets[depth]

		// The current depth matches the prefix's stride count, meaning this is the final
		// node for this prefix. We insert it directly into this node's prefix table.
		if depth == strideCount {
			return n.InsertPrefix(art.PfxToIdx(octet, modBits), val)
		}

		// No child exists at this octet path. Instead of creating intermediate nodes
		// for the remaining strides, we path-compress the rest of the prefix into a single child slot.
		if !n.Children.Test(octet) {
			// If the prefix is perfectly aligned with the next stride boundary (e.g., /16 at depth 1),
			// it acts as a default route for everything below it. We store it as a FringeNode.
			// Otherwise, it has trailing bits or crosses boundaries, so we store it as a LeafNode.
			if IsFringe(depth, pfxLen) {
				return n.InsertChild(octet, NewFringeNode(val))
			}
			return n.InsertChild(octet, NewLeafNode(pfx, val))
		}

		// A child already exists at this octet path. Retrieve it to either continue
		// our descent along the strides or resolve a structural collision with a compressed node.
		kid := n.MustGetChild(octet)

		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			// Standard intermediate node: descend to the next trie level.
			n = kid

		case *LeafNode[V]:
			// Collision with an existing path-compressed LeafNode.
			// If it's the exact same prefix, simply update the value.
			if kid.Prefix == pfx {
				kid.Value = val
				return true
			}

			// Collision resolution: the paths diverge.
			// 1. Create a new intermediate node.
			// 2. Push the existing leaf down into this new node.
			// 3. Replace the current child slot with the new node.
			// 4. Descend into the new node to continue inserting 'pfx'.
			newNode := new(_NODE_TYPE[V])
			newNode.Insert(kid.Prefix, kid.Value, depth+1)

			n.InsertChild(octet, newNode)
			n = newNode

		case *FringeNode[V]:
			// Collision with an existing path-compressed FringeNode.
			// If the incoming prefix is also a fringe at this depth, update the value.
			if IsFringe(depth, pfxLen) {
				kid.Value = val
				return true
			}

			// Collision resolution:
			// The existing FringeNode acts as a catch-all (default route) for this sub-trie.
			// To allow the incoming prefix to branch further, we expand the FringeNode
			// into a full intermediate node and place its value at the default route index (1).
			newNode := new(_NODE_TYPE[V])
			newNode.InsertPrefix(1, kid.Value)

			n.InsertChild(octet, newNode)
			n = newNode

		default:
			panic("logic error, wrong node type")
		}
	}
	panic("unreachable")
}

// InsertPersist adds or updates a network prefix and its associated value in the trie
// using Copy-On-Write (COW) semantics. Traversal begins at the specified byte depth.
//
// Unlike [Insert], InsertPersist ensures structural integrity of the existing tree
// by cloning internal nodes along the descent path (Copy-On-Write) before mutation.
//
// Parameters:
//   - cloneFn: The function used to clone values (V).
//   - pfx: The network prefix to insert (must be in canonical/masked form).
//   - val: The value to associate with the prefix.
//   - depth: The current depth in the trie (0-based byte index).
//
// Returns true if an existing prefix was updated, false if a new insertion occurred.
func (n *_NODE_TYPE[V]) InsertPersist(cloneFn func(V) V, pfx netip.Prefix, val V, depth int) (exists bool) {
	ip := pfx.Addr() // the pfx must be in canonical form
	pfxLen := pfx.Bits()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// Traverse the prefix's octets. Each depth corresponds to an 8-bit stride.
	// We descend through the trie until we either reach the final stride (depth == strideCount)
	// or find an empty child slot where we can path-compress the remaining strides.
	for ; depth < len(octets); depth++ {
		octet := octets[depth]

		// The current depth matches the prefix's stride count, meaning this is the final
		// node for this prefix. We insert it directly into this node's prefix table.
		if depth == strideCount {
			return n.InsertPrefix(art.PfxToIdx(octet, modBits), val)
		}

		// No child exists at this octet path. Instead of creating intermediate nodes
		// for the remaining strides, we path-compress the rest of the prefix into a single child slot.
		if !n.Children.Test(octet) {
			// If the prefix is perfectly aligned with the next stride boundary (e.g., /16 at depth 1),
			// it acts as a default route for everything below it. We store it as a FringeNode.
			// Otherwise, it has trailing bits or crosses boundaries, so we store it as a LeafNode.
			if IsFringe(depth, pfxLen) {
				return n.InsertChild(octet, NewFringeNode(val))
			}
			return n.InsertChild(octet, NewLeafNode(pfx, val))
		}

		// A child already exists at this octet path. Retrieve it to either continue
		// our descent along the strides or resolve a structural collision with a compressed node.
		kid := n.MustGetChild(octet)

		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			// Standard intermediate node: Clone the traversed path to maintain persistence (COW).
			// We clone the child node before modifying it, then replace the current child slot.
			kid = kid.CloneFlat(cloneFn)
			n.InsertChild(octet, kid)
			n = kid

		case *LeafNode[V]:
			// Collision with an existing path-compressed LeafNode.
			// If it's the exact same prefix, simply update the value.
			if kid.Prefix == pfx {
				kid.Value = val
				return true
			}

			// Collision resolution: the paths diverge.
			// 1. Create a new intermediate node.
			// 2. Push the existing leaf down into this new node.
			// 3. Replace the current child slot with the new node.
			// 4. Descend into the new node to continue inserting 'pfx'.
			newNode := new(_NODE_TYPE[V])
			newNode.Insert(kid.Prefix, kid.Value, depth+1)

			n.InsertChild(octet, newNode)
			n = newNode

		case *FringeNode[V]:
			// Collision with an existing path-compressed FringeNode.
			// If the incoming prefix is also a fringe at this depth, update the value.
			if IsFringe(depth, pfxLen) {
				kid.Value = val
				return true
			}

			// Collision resolution:
			// The existing FringeNode acts as a catch-all (default route) for this sub-trie.
			// To allow the incoming prefix to branch further, we expand the FringeNode
			// into a full intermediate node and place its value at the default route index (1).
			newNode := new(_NODE_TYPE[V])
			newNode.InsertPrefix(1, kid.Value)

			n.InsertChild(octet, newNode)
			n = newNode

		default:
			panic("logic error, wrong node type")
		}
	}
	panic("unreachable")
}

// PurgeAndCompress performs bottom-up trie maintenance to restore path compression
// after a deletion. It unwinds the provided stack of parent nodes, identifying
// nodes that have become sparse (i.e., containing only a single prefix or a single
// child node) and prunes them by promoting the underlying entries to the parent level.
//
// This ensures the trie remains memory-efficient by collapsing redundant intermediate
// nodes back into path-compressed LeafNodes or FringeNodes whenever possible.
//
// Parameters:
//   - stack: Array of parent nodes to process during bottom-up unwinding.
//   - octets: The full path of octets leading to the current node.
//   - is4: True for IPv4 processing, false for IPv6.
func (n *_NODE_TYPE[V]) PurgeAndCompress(stack []*_NODE_TYPE[V], octets []uint8, is4 bool) {
	// Iterate backwards through the ancestor stack to prune nodes from the bottom up.
	for depth := len(stack) - 1; depth >= 0; depth-- {
		parent := stack[depth]
		octet := octets[depth]

		// Check if the current node is redundant.
		// A node may be redundant if it contains exactly one entry (either a prefix or
		// a compressed child node).
		pfxCount := n.PrefixCount()
		childCount := n.ChildCount()

		// If it contains more than one entry, it is always structurally significant and cannot be pruned.
		if pfxCount+childCount > 1 {
			return
		}

		switch {
		case childCount == 1:
			// The node has exactly one child. We determine if it is a path node,
			// a compressed LeafNode, or a compressed FringeNode.
			anyKid := n.Children.Items[0]

			switch kid := anyKid.(type) {
			case *_NODE_TYPE[V]:
				// The child is an intermediate path node; the tree structure is required
				// at this level. Compression cannot proceed further up.
				return
			case *LeafNode[V]:
				// The child is a compressed LeafNode. Prune the current node
				// and re-insert the leaf into the parent to elevate it.
				parent.DeleteChild(octet)
				parent.Insert(kid.Prefix, kid.Value, depth)
			case *FringeNode[V]:
				// The child is a compressed FringeNode. Prune the current node
				// and re-insert the fringe as a leaf into the parent.
				parent.DeleteChild(octet)

				// Reconstruct the full prefix for the fringe, as path compression
				// requires the entire CIDR path, not just the remainder.
				// depth is the parent's depth, so we offset by 1 for the kid's position.
				singleAddr, _ := n.Children.FirstSet()
				fringePfx := CidrForFringe(octets, depth+1, is4, singleAddr)

				parent.Insert(fringePfx, kid.Value, depth)
			}

		case pfxCount == 1:
			// The node has exactly one prefix. Prune the node and elevate the
			// prefix to the parent level as a leaf/fringe.
			parent.DeleteChild(octet)

			// Retrieve the single prefix stored in this node.
			idx, _ := n.Prefixes.FirstSet()
			val := n.MustGetPrefix(idx)

			// Reconstruct the prefix from the path for re-insertion.
			path := StridePath{}
			copy(path[:], octets)
			pfx := CidrFromPath(path, depth+1, is4, idx)

			parent.Insert(pfx, val, depth)
		default:
			panic("unreachable")
		}

		// Move up to the next parent in the stack to continue pruning.
		n = parent
	}
}

// Delete removes the prefix from the trie rooted at n and returns true if the
// prefix existed, false if it was not found. The prefix must be in canonical
// (masked) form.
//
// The trie uses path compression, so a prefix may be stored in one of three ways:
//   - In the current node's prefix table when the prefix length aligns exactly
//     with the stride boundary at this depth (depth == strideCount).
//   - As a path-compressed FringeNode in a child slot for stride-aligned prefixes
//     (e.g. /8, /16, /24); occurs at depth == strideCount-1.
//   - As a path-compressed LeafNode in a child slot for prefixes otherwise.
//
// After a successful deletion, PurgeAndCompress walks the ancestor stack to prune
// now-empty nodes and restore path compression upward.
func (n *_NODE_TYPE[V]) Delete(pfx netip.Prefix) (exists bool) {
	ip := pfx.Addr() // pfx must be in canonical (masked) form
	pfxLen := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// Record ancestor nodes as we descend; PurgeAndCompress uses this stack to
	// walk back up and clean up empty or re-compressible nodes after deletion.
	stack := [MaxTreeDepth]*_NODE_TYPE[V]{}

	for depth, octet := range octets {
		depth &= DepthMask // BCE hint; keep Delete on the fast path

		stack[depth] = n // record current node before descending

		// At the stride boundary, the prefix is stored directly in this node's
		// prefix table.
		if depth == strideCount {
			if exists = n.DeletePrefix(art.PfxToIdx(octet, modBits)); !exists {
				return false
			}

			// prune now-empty nodes and re-compress the path upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true
		}

		// no child node exists at this octet; the prefix is not in the trie
		if !n.Children.Test(octet) {
			return false
		}

		// A child node exists at this octet path, retrieve it.
		kid := n.MustGetChild(octet)

		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			n = kid // descend to the next trie level

		case *FringeNode[V]:
			// A FringeNode holds a single stride-aligned prefix (/8, /16, ...).
			// If pfx does not qualify as a fringe at this depth, it cannot be here.
			if !IsFringe(depth, pfxLen) {
				return false
			}

			n.DeleteChild(octet)

			// prune now-empty nodes and re-compress the path upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true

		case *LeafNode[V]:
			// A LeafNode holds exactly one path-compressed prefix.
			// Compare using the canonical (masked) form for an exact match.
			if kid.Prefix != pfx {
				return false
			}

			n.DeleteChild(octet)

			// prune now-empty nodes and re-compress the path upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// DeletePersist removes the prefix from the trie rooted at n using Copy-On-Write (COW) semantics.
// It returns true if the prefix existed, false if it was not found. The prefix must be in
// canonical (masked) form.
//
// Like [Delete], this method uses path compression. However, DeletePersist ensures
// the structural integrity of the existing tree by cloning internal nodes along the
// descent path (COW) before mutation.
//
// After a successful deletion, PurgeAndCompress walks the ancestor stack to prune
// now-empty nodes and restore path compression upward.
func (n *_NODE_TYPE[V]) DeletePersist(cloneFn func(V) V, pfx netip.Prefix) (exists bool) {
	ip := pfx.Addr() // pfx must be in canonical (masked) form
	pfxLen := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// Record ancestor nodes as we descend; PurgeAndCompress uses this stack to
	// walk back up and clean up empty or re-compressible nodes after deletion.
	// Since this is a COW operation, we store the cloned nodes here.
	stack := [MaxTreeDepth]*_NODE_TYPE[V]{}

	for depth, octet := range octets {
		depth &= DepthMask // BCE hint; keep DeletePersist on the fast path
		stack[depth] = n   // record current node before descending

		// At the stride boundary, the prefix is stored directly in this node's
		// prefix table.
		if depth == strideCount {
			if exists = n.DeletePrefix(art.PfxToIdx(octet, modBits)); !exists {
				return false
			}

			// prune now-empty nodes and re-compress the path upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true
		}

		// no child node exists at this octet; the prefix is not in the trie
		if !n.Children.Test(octet) {
			return false
		}

		// A child node exists at this octet path, retrieve it to either continue
		// our descent or perform a persistent delete on a compressed node.
		kid := n.MustGetChild(octet)

		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			// Standard intermediate node: Clone the traversed path to maintain
			// persistence (COW). We clone the child node before modifying it,
			// then replace the current child slot.
			kid = kid.CloneFlat(cloneFn)
			n.InsertChild(octet, kid)
			n = kid
			continue

		case *FringeNode[V]:
			// A FringeNode holds a single stride-aligned prefix (/8, /16, ...).
			// If pfx does not qualify as a fringe at this depth, it cannot be here.
			if !IsFringe(depth, pfxLen) {
				return false
			}

			n.DeleteChild(octet)

			// prune now-empty nodes and re-compress the path upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true

		case *LeafNode[V]:
			// A LeafNode holds exactly one path-compressed prefix.
			// Compare using the canonical (masked) form for an exact match.
			if kid.Prefix != pfx {
				return false
			}

			n.DeleteChild(octet)

			// prune now-empty nodes and re-compress the path upwards
			n.PurgeAndCompress(stack[:depth], octets, is4)
			return true

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// Get retrieves the value associated with the given network prefix.
// Traversal descends through the trie using the prefix's octets.
//
// The lookup handles path compression transparently:
//   - If the path matches an internal node at the target stride, the value is retrieved
//     from the node's prefix table.
//   - If the path leads to a compressed LeafNode or FringeNode, the function verifies
//     the prefix match before returning the value.
//
// Parameters:
//   - pfx: The network prefix to look up (must be in canonical form).
//
// Returns:
//   - val: The value associated with the prefix (zero value if not found).
//   - exists: True if the prefix was found, false otherwise.
func (n *_NODE_TYPE[V]) Get(pfx netip.Prefix) (val V, exists bool) {
	// The prefix must be provided in canonical (masked) form for correct trie traversal.
	ip := pfx.Addr()
	pfxLen := pfx.Bits()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// Traverse the trie octet by octet based on the prefix path.
	for depth, octet := range octets {
		// At the target stride boundary, the prefix is expected in this node's
		// prefix table.
		if depth == strideCount {
			return n.GetPrefix(art.PfxToIdx(octet, modBits))
		}

		// If no child exists at this path, the prefix is not in the trie.
		kidAny, ok := n.GetChild(octet)
		if !ok {
			return val, false
		}

		// Identify the node type at this path segment.
		switch kid := kidAny.(type) {
		case *_NODE_TYPE[V]:
			// Standard intermediate node: descend to the next level.
			n = kid

		case *FringeNode[V]:
			// Reached a path-compressed FringeNode.
			// Verify if the prefix qualifies as a fringe at this depth to return a match.
			if IsFringe(depth, pfxLen) {
				return kid.Value, true
			}
			return val, false

		case *LeafNode[V]:
			// Reached a path-compressed LeafNode.
			// Check if the stored prefix matches the lookup prefix exactly.
			if kid.Prefix == pfx {
				return kid.Value, true
			}
			return val, false

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// Contains returns true if an index (idx) has any matching longest-prefix
// in the current node’s prefix table.
//
// This function performs a presence check without retrieving the associated value.
// It is faster than a full lookup, as it only tests for intersection with the
// backtracking bitset for the given index.
//
// The prefix table is structured as a complete binary tree (CBT), and LPM testing
// is done via a bitset operation that maps the traversal path from the given index
// toward its possible ancestors.
func (n *_NODE_TYPE[V]) Contains(idx uint8) bool {
	return n.Prefixes.Overlaps(&lpm.LookupTbl[idx])
}

// ### GENERATE SKIP_LITE START ###

// LookupIdx performs a longest-prefix match (LPM) lookup for the given index (idx)
// within the 8-bit stride-based prefix table at this trie depth.
//
// The function returns the matched base index, associated value, and true if a
// matching prefix exists at this level; otherwise, ok is false.
//
// Internally, the prefix table is organized as a complete binary tree (CBT) indexed
// via the baseIndex function. Unlike the original ART algorithm, this implementation
// does not use an allotment-based approach. Instead, it performs CBT backtracking
// using a bitset-based operation with a precomputed backtracking pattern specific to idx.
func (n *_NODE_TYPE[V]) LookupIdx(idx uint8) (top uint8, val V, ok bool) {
	// top is the idx of the longest-prefix-match
	if top, ok = n.Prefixes.AndTop(&lpm.LookupTbl[idx]); ok {
		return top, n.MustGetPrefix(top), true
	}
	return top, val, ok
}

// Lookup is just a simple wrapper for LookupIdx.
func (n *_NODE_TYPE[V]) Lookup(idx uint8) (val V, ok bool) {
	_, val, ok = n.LookupIdx(idx)
	return val, ok
}

// ### GENERATE SKIP_LITE END ###

// Modify performs an in-place modification of a prefix using the provided callback function.
// The callback receives the current value (if found) and existence flag, and returns
// a new value and deletion flag.
//
// Modify returns the size delta (-1, 0, +1).
// This method handles path traversal, node creation for new paths, and automatic
// purge/compress operations after deletions.
//
// Parameters:
//   - pfx: The network prefix to modify (must be in canonical form)
//   - cb: Callback function that receives (currentValue, exists) and returns (newValue, deleteFlag)
//
// Returns:
//   - delta: Size change (-1 for delete, 0 for update/noop, +1 for insert)
func (n *_NODE_TYPE[V]) Modify(pfx netip.Prefix, cb func(val V, found bool) (_ V, del bool)) (delta int) {
	var zero V

	ip := pfx.Addr()
	pfxLen := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// record the nodes on the path to the deleted node, needed to purge
	// and/or path compress nodes after the deletion of a prefix
	stack := [MaxTreeDepth]*_NODE_TYPE[V]{}

	// find the proper trie node to update prefix
	for depth, octet := range octets {
		depth &= DepthMask // BCE

		// push current node on stack for path recording
		stack[depth] = n

		// The current depth matches the prefix's stride count, meaning this is the final
		// stride for this prefix. Insert or update it directly in this node's prefix table.
		if depth == strideCount {
			idx := art.PfxToIdx(octet, modBits)

			oldVal, existed := n.GetPrefix(idx)
			newVal, del := cb(oldVal, existed)

			// update size if necessary
			switch {
			case !existed && del: // no-op
				return 0

			case existed && del: // delete
				n.DeletePrefix(idx)
				// remove now-empty nodes and re-path-compress upwards
				n.PurgeAndCompress(stack[:depth], octets, is4)
				return -1

			case !existed: // insert
				n.InsertPrefix(idx, newVal)
				return 1

			case existed: // update
				n.InsertPrefix(idx, newVal)
				return 0

			default:
				panic("unreachable")
			}

		}

		// go down in tight loop to last octet
		if !n.Children.Test(octet) {
			// insert prefix path compressed

			newVal, del := cb(zero, false)
			if del {
				return 0
			}

			// insert
			if IsFringe(depth, pfxLen) {
				n.InsertChild(octet, NewFringeNode(newVal))
			} else {
				n.InsertChild(octet, NewLeafNode(pfx, newVal))
			}

			return 1
		}

		// n.children.Test(octet) == true
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			n = kid // descend down to next trie level
			continue

		case *LeafNode[V]:
			oldVal := kid.Value

			// update existing value if prefixes are equal
			if kid.Prefix == pfx {
				newVal, del := cb(oldVal, true)

				if !del {
					kid.Value = newVal
					return 0
				}

				// delete
				n.DeleteChild(octet)

				// remove now-empty nodes and re-path-compress upwards
				n.PurgeAndCompress(stack[:depth], octets, is4)

				return -1
			}

			// stop if this is a no-op for zero values
			newVal, del := cb(zero, false)
			if del {
				return 0
			}

			// create new node
			// insert new child at current leaf position (octet)
			newNode := new(_NODE_TYPE[V])
			n.InsertChild(octet, newNode)

			// push the leaf down
			// insert pfx with newVal in new node
			newNode.Insert(kid.Prefix, kid.Value, depth+1)
			newNode.Insert(pfx, newVal, depth+1)

			return 1

		case *FringeNode[V]:
			// update existing value if prefix is fringe
			if IsFringe(depth, pfxLen) {
				newVal, del := cb(kid.Value, true)
				if !del {
					kid.Value = newVal
					return 0
				}

				// delete
				n.DeleteChild(octet)

				// remove now-empty nodes and re-path-compress upwards
				n.PurgeAndCompress(stack[:depth], octets, is4)

				return -1
			}

			// stop if this is a no-op for zero values
			newVal, del := cb(zero, false)
			if del {
				return 0
			}

			// create new node
			// insert new child at current leaf position (octet)
			newNode := new(_NODE_TYPE[V])
			n.InsertChild(octet, newNode)

			// push the fringe down, it becomes a default route (idx=1)
			// insert pfx with newVal in new node
			newNode.InsertPrefix(1, kid.Value)
			newNode.Insert(pfx, newVal, depth+1)

			return 1

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable")
}

// EqualRec performs recursive structural equality comparison between two nodes.
// Compares prefix and child bitsets, then recursively compares all stored values
// and child nodes. Returns true if the nodes and their entire subtrees are
// structurally and semantically identical, false otherwise.
//
// The comparison handles different node types (internal nodes, leafNodes, fringeNodes)
// and uses the equal function for value comparisons to support custom equality logic.
func (n *_NODE_TYPE[V]) EqualRec(o *_NODE_TYPE[V]) bool {
	if n == nil || o == nil {
		return n == o
	}
	if n == o {
		return true
	}

	if n.Prefixes.BitSet256 != o.Prefixes.BitSet256 {
		return false
	}

	if n.Children.BitSet256 != o.Children.BitSet256 {
		return false
	}

	// ### GENERATE SKIP_LITE START ###
	for idx, nVal := range n.AllIndices() {
		oVal := o.MustGetPrefix(idx) // MustGet is ok, bitsets are equal
		if !value.Equal(nVal, oVal) {
			return false
		}
	}
	// ### GENERATE SKIP_LITE END ###

	for addr, nKid := range n.AllChildren() {
		oKid := o.MustGetChild(addr) // MustGet is ok, bitsets are equal

		switch nKid := nKid.(type) {
		case *_NODE_TYPE[V]:
			// oKid must also be a node
			oKid, ok := oKid.(*_NODE_TYPE[V])
			if !ok {
				return false
			}

			// compare rec-descent
			if !nKid.EqualRec(oKid) {
				return false
			}

		case *LeafNode[V]:
			// oKid must also be a leaf
			oKid, ok := oKid.(*LeafNode[V])
			if !ok {
				return false
			}

			// compare prefixes
			if nKid.Prefix != oKid.Prefix {
				return false
			}

			// ### GENERATE SKIP_LITE START ###

			// compare values
			if !value.Equal(nKid.Value, oKid.Value) {
				return false
			}

			// ### GENERATE SKIP_LITE END ###

		case *FringeNode[V]:
			// oKid must also be a fringe
			oKid, ok := oKid.(*FringeNode[V])
			if !ok {
				return false
			}
			_ = oKid // mark as used for LiteNode (where value checks are stripped)

			// ### GENERATE SKIP_LITE START ###

			// compare values
			if !value.Equal(nKid.Value, oKid.Value) {
				return false
			}

			// ### GENERATE SKIP_LITE END ###

		default:
			panic("logic error, wrong node type")
		}
	}

	return true
}

// DumpRec recursively descends the trie rooted at n and writes a human-readable
// representation of each visited node to w.
//
// It returns immediately if n is nil or empty. For each visited internal node
// it calls dump to write the node's representation, then iterates its child
// addresses and recurses into children of type *_NODE_TYPE[V] (internal subnodes).
// The path slice and depth together represent the byte-wise path
// from the root to the current node; depth is incremented for each recursion.
// The is4 flag controls IPv4/IPv6 formatting used by dump.
func (n *_NODE_TYPE[V]) DumpRec(w io.Writer, path StridePath, depth int, is4 bool) {
	if n == nil || n.IsEmpty() {
		return
	}

	// dump this node
	n.dump(w, path, depth, is4)

	// node may have children, rec-descent down
	for addr, child := range n.AllChildren() {
		if kid, ok := child.(*_NODE_TYPE[V]); ok {
			path[depth] = addr
			kid.DumpRec(w, path, depth+1, is4)
		}
	}
}

// dump writes a human-readable representation of the node to `w`.
// It prints the node type, depth, formatted path (IPv4 vs IPv6 controlled by `is4`),
// and bit count, followed by any stored prefixes (and their values when applicable),
// the set of child octets, and any path-compressed leaves or fringe entries.
func (n *_NODE_TYPE[V]) dump(w io.Writer, path StridePath, depth int, is4 bool) {
	bits := depth * strideLen
	indent := strings.Repeat(".", depth)

	// printing values if V is not the empty struct{}
	printValues := !value.IsEmptyStruct[V]()

	// node type with depth and octet path and bits.
	fmt.Fprintf(w, "\n%s[%s] depth:  %d path: [%s] / %d\n",
		indent, n.hasType(), depth, ipStridePath(path, depth, is4), bits)

	if nPfxCount := n.PrefixCount(); nPfxCount != 0 {
		allIndices := n.Prefixes.Bits()

		// print the baseIndices for this node.
		fmt.Fprintf(w, "%sindexs(#%d): %v\n", indent, nPfxCount, allIndices)

		// print the prefixes for this node
		fmt.Fprintf(w, "%sprefxs(#%d):", indent, nPfxCount)

		for _, idx := range allIndices {
			pfx := CidrFromPath(path, depth, is4, idx)
			fmt.Fprintf(w, " %s", pfx)
		}

		fmt.Fprintln(w)

		// skip printing values if V is empty struct
		if printValues {

			// print the values for this node
			fmt.Fprintf(w, "%svalues(#%d):", indent, nPfxCount)

			for _, idx := range allIndices {
				val := n.MustGetPrefix(idx)
				fmt.Fprintf(w, " %#v", val)
			}

			fmt.Fprintln(w)
		}
	}

	if cc := n.ChildCount(); cc != 0 {
		allAddrs := make([]uint8, 0, cc)
		childAddrs := make([]uint8, 0, cc)
		leafAddrs := make([]uint8, 0, cc)
		fringeAddrs := make([]uint8, 0, cc)

		// the node has recursive child nodes or path-compressed leaves
		for addr, child := range n.AllChildren() {
			allAddrs = append(allAddrs, addr)

			switch child.(type) {
			case *_NODE_TYPE[V]:
				childAddrs = append(childAddrs, addr)
				continue

			case *FringeNode[V]:
				fringeAddrs = append(fringeAddrs, addr)

			case *LeafNode[V]:
				leafAddrs = append(leafAddrs, addr)

			default:
				panic("logic error, wrong node type")
			}
		}

		// print the children for this node.
		fmt.Fprintf(w, "%soctets(#%d): %v\n", indent, len(allAddrs), allAddrs)

		if leafCount := len(leafAddrs); leafCount > 0 {
			// print the pathcomp prefixes for this node
			fmt.Fprintf(w, "%sleaves(#%d):", indent, leafCount)

			for _, addr := range leafAddrs {
				kid := n.MustGetChild(addr).(*LeafNode[V])

				// skip printing values if V is empty struct
				if printValues {
					fmt.Fprintf(w, " %s:{%s, %v}", addrFmt(addr, is4), kid.Prefix, kid.Value)
				} else {
					fmt.Fprintf(w, " %s:{%s}", addrFmt(addr, is4), kid.Prefix)
				}
			}

			fmt.Fprintln(w)
		}

		if fringeCount := len(fringeAddrs); fringeCount > 0 {
			// print the pathcomp prefixes for this node
			fmt.Fprintf(w, "%sfringe(#%d):", indent, fringeCount)

			for _, addr := range fringeAddrs {
				fringePfx := CidrForFringe(path[:], depth, is4, addr)

				kid := n.MustGetChild(addr).(*FringeNode[V])

				// skip printing values if V is empty struct
				if printValues {
					fmt.Fprintf(w, " %s:{%s, %v}", addrFmt(addr, is4), fringePfx, kid.Value)
				} else {
					fmt.Fprintf(w, " %s:{%s}", addrFmt(addr, is4), fringePfx)
				}
			}

			fmt.Fprintln(w)
		}

		if childCount := len(childAddrs); childCount > 0 {
			// print the next child
			fmt.Fprintf(w, "%schilds(#%d):", indent, childCount)

			for _, addr := range childAddrs {
				fmt.Fprintf(w, " %s", addrFmt(addr, is4))
			}

			fmt.Fprintln(w)
		}

	}
}

// DumpString traverses the trie to the node at the specified depth along the given
// octet path and returns its string representation via Dump.
//
// If the path is invalid or encounters an unexpected node type during traversal,
// it returns an error message string instead.
//
// Parameters:
//   - octets: The path of octets to follow from the root
//   - depth: Target depth to reach before dumping (0-based byte index)
//   - is4: True for IPv4 formatting, false for IPv6
//
// Returns a formatted string representation of the target node or an error message.
func (n *_NODE_TYPE[V]) DumpString(octets []uint8, depth int, is4 bool) string {
	path := StridePath{}
	copy(path[:], octets)

	buf := new(strings.Builder)
	for i := range depth {
		anyKid, ok := n.GetChild(path[i])
		if !ok {
			return fmt.Sprintf("ERROR: kid for %v[%d] is NOT set in node\n", octets, i)
		}

		kid, ok := anyKid.(*_NODE_TYPE[V])
		if !ok {
			return fmt.Sprintf("ERROR: kid for %v[%d] is NO %s\n", octets, i, "_NODE_TYPE[V]")
		}

		// traverse
		n = kid
	}

	n.dump(buf, path, depth, is4)
	return buf.String()
}

// hasType classifies the given node into one of the nodeType values.
//
// It inspects immediate statistics (prefix count, child count, node, leaf and
// fringe counts) for the node and returns:
//   - nullNode: no prefixes and no children
//   - stopNode: has children but no subnodes (nodes == 0)
//   - halfNode: contains at least one leaf or fringe and also has subnodes, but
//     no prefixes
//   - fullNode: has prefixes and also has subnodes
//   - pathNode: has subnodes only (no prefixes, leaves, or fringes)
//
// The order of these checks is significant to ensure the correct classification.
func (n *_NODE_TYPE[V]) hasType() nodeType {
	s := n.Stats()

	// the order is important
	switch {
	case s.Prefixes == 0 && s.Children == 0:
		return nullNode
	case s.SubNodes == 0:
		return stopNode
	case (s.Leaves > 0 || s.Fringes > 0) && s.SubNodes > 0 && s.Prefixes == 0:
		return halfNode
	case (s.Prefixes > 0 || s.Leaves > 0 || s.Fringes > 0) && s.SubNodes > 0:
		return fullNode
	case (s.Prefixes == 0 && s.Leaves == 0 && s.Fringes == 0) && s.SubNodes > 0:
		return pathNode
	default:
		panic(fmt.Sprintf("UNREACHABLE: pfx: %d, chld: %d, node: %d, leaf: %d, fringe: %d",
			s.Prefixes, s.Children, s.SubNodes, s.Leaves, s.Fringes))
	}
}

// Stats returns immediate statistics for n: counts of prefixes and children,
// and a classification of each child into nodes, leaves, or fringes.
// It inspects only the direct children of n (not the whole subtree).
// Panics if a child has an unexpected concrete type.
func (n *_NODE_TYPE[V]) Stats() (s StatsT) {
	s.Prefixes = n.PrefixCount()
	s.Children = n.ChildCount()

	for _, child := range n.AllChildren() {
		switch child.(type) {
		case *_NODE_TYPE[V]:
			s.SubNodes++

		case *FringeNode[V]:
			s.Fringes++

		case *LeafNode[V]:
			s.Leaves++

		default:
			panic("logic error, wrong node type")
		}
	}

	return s
}

// StatsRec returns aggregated statistics for the subtree rooted at n.
//
// It walks the node tree recursively and sums immediate counts (prefixes and
// child slots) plus the number of nodes, leaves, and fringe nodes in the
// subtree. If n is nil or empty, a zeroed stats is returned. The returned
// SubNodes count includes the current node. The function will panic if a child
// has an unexpected concrete type.
func (n *_NODE_TYPE[V]) StatsRec() (s StatsT) {
	if n == nil || n.IsEmpty() {
		return s
	}

	s.Prefixes = n.PrefixCount()
	s.Children = n.ChildCount()
	s.SubNodes = 1 // this node
	s.Leaves = 0
	s.Fringes = 0

	for _, child := range n.AllChildren() {
		switch kid := child.(type) {
		case *_NODE_TYPE[V]:
			// rec-descent
			rs := kid.StatsRec()

			s.Prefixes += rs.Prefixes
			s.Children += rs.Children
			s.SubNodes += rs.SubNodes
			s.Leaves += rs.Leaves
			s.Fringes += rs.Fringes

		case *FringeNode[V]:
			s.Fringes++

		case *LeafNode[V]:
			s.Leaves++

		default:
			panic("logic error, wrong node type")
		}
	}

	return s
}

// FprintRec recursively prints a hierarchical CIDR tree representation
// starting from this node to the provided writer. The output shows the
// routing table structure in human-readable format for debugging and analysis.
func (n *_NODE_TYPE[V]) FprintRec(w io.Writer, parent TrieItem[V], pad string) error {
	// recursion stop condition
	if n == nil || n.IsEmpty() {
		return nil
	}

	// get direct covered childs for this parent ...
	directItems := n.DirectItemsRec(parent.Idx, parent.Path, parent.Depth, parent.Is4)

	// sort them by netip.Prefix, not by baseIndex
	slices.SortFunc(directItems, func(a, b TrieItem[V]) int {
		return CmpPrefix(a.Cidr, b.Cidr)
	})

	// printing values if V is not the empty struct{}
	printValues := !value.IsEmptyStruct[V]()

	// for all direct item under this node ...
	for i, item := range directItems {
		// symbols used in tree
		glyph := "├─ "
		space := "│  "

		// ... treat last kid special
		if i == len(directItems)-1 {
			glyph = "└─ "
			space = "   "
		}

		var err error
		// val is the empty struct, don't print it
		if printValues {
			_, err = fmt.Fprintf(w, "%s%s (%v)\n", pad+glyph, item.Cidr, item.Val)
		} else {
			// skip printing values if V is empty struct
			_, err = fmt.Fprintf(w, "%s%s\n", pad+glyph, item.Cidr)
		}

		if err != nil {
			return err
		}

		// rec-descent with this item as parent
		nextNode, _ := item.Node.(*_NODE_TYPE[V])
		if err = nextNode.FprintRec(w, item, pad+space); err != nil {
			return err
		}
	}

	return nil
}

// DirectItemsRec, returns the direct covered items by parent.
// It's a complex recursive function, you have to know the data structure
// by heart to understand this function!
func (n *_NODE_TYPE[V]) DirectItemsRec(parentIdx uint8, path StridePath, depth int, is4 bool) (directItems []TrieItem[V]) {
	// recursion stop condition
	if n == nil || n.IsEmpty() {
		return nil
	}

	// prefixes:
	// for all idx's (prefixes mapped by baseIndex) in this node
	// do a longest-prefix-match
	for idx, val := range n.AllIndices() {
		// tricky part, skip self
		// test with next possible lpm (idx>>1), it's a complete binary tree
		nextIdx := idx >> 1

		// fast skip, lpm not possible
		if nextIdx < parentIdx {
			continue
		}

		// do a longest-prefix-match
		lpm, _, _ := n.LookupIdx(nextIdx)

		// be aware, 0 is here a possible value for parentIdx and lpm (if not found)
		if lpm == parentIdx {
			// prefix is directly covered by parent

			item := TrieItem[V]{
				Node:  n,
				Is4:   is4,
				Path:  path,
				Depth: depth,
				Idx:   idx,
				// get the prefix back from trie
				Cidr: CidrFromPath(path, depth, is4, idx),
				Val:  val,
			}

			directItems = append(directItems, item)
		}
	}

	// children:
	for addr, child := range n.AllChildren() {
		hostIdx := art.OctetToIdx(addr)

		// do a longest-prefix-match
		lpm, _, _ := n.LookupIdx(hostIdx)

		// be aware, 0 is here a possible value for parentIdx and lpm (if not found)
		if lpm == parentIdx {
			// child is directly covered by parent
			switch kid := child.(type) {
			case *_NODE_TYPE[V]: // traverse rec-descent, call with next child node,
				// next trie level, set parentIdx to 0, adjust path and depth
				path[depth] = addr
				directItems = append(directItems, kid.DirectItemsRec(0, path, depth+1, is4)...)

			case *LeafNode[V]: // path-compressed child, stops recursion for this child
				item := TrieItem[V]{
					Node: nil,
					Is4:  is4,
					Cidr: kid.Prefix,
					Val:  kid.Value,
				}
				directItems = append(directItems, item)

			case *FringeNode[V]: // path-compressed fringe, stops recursion for this child
				item := TrieItem[V]{
					Node: nil,
					Is4:  is4,
					// get the prefix back from trie
					Cidr: CidrForFringe(path[:], depth, is4, addr),
					Val:  kid.Value,
				}
				directItems = append(directItems, item)

			default:
				panic("logic error, wrong node type")
			}
		}
	}

	return directItems
}

// UnionRec recursively merges another node o into the receiver node n.
//
// All prefix and child entries from o are cloned and inserted into n.
// If a prefix already exists in n, its value is overwritten by the value from o,
// and the duplicate is counted in the return value. This count can later be used
// to update size-related metadata in the parent trie.
//
// The union handles all possible combinations of child node types (node, leaf, fringe)
// between the two nodes. Structural conflicts are resolved by creating new intermediate
// *_NODE_TYPE[V] objects and pushing both children further down the trie. Leaves and fringes
// are also recursively relocated as needed to preserve prefix semantics.
//
// The merge operation is destructive on the receiver n, but leaves the source node o unchanged.
//
// Returns the number of duplicate prefixes that were overwritten during merging.
func (n *_NODE_TYPE[V]) UnionRec(cloneFn func(V) V, o *_NODE_TYPE[V], depth int) (duplicates int) {
	if cloneFn == nil {
		cloneFn = func(v V) V { return v }
	}

	// for all prefixes in other node do ...
	for oIdx := range o.Prefixes.All() {
		// clone/copy the value from other node at idx
		val := o.MustGetPrefix(oIdx)
		clonedVal := cloneFn(val)

		// insert/overwrite cloned value from o into n
		if n.InsertPrefix(oIdx, clonedVal) {
			// this prefix is duplicate in n and o
			duplicates++
		}
	}

	// for all child addrs in other node do ...
	for addr := range o.Children.All() {
		otherChild := o.MustGetChild(addr)
		thisChild, thisExists := n.GetChild(addr)

		// Use helper function to handle all 4x3 combinations
		duplicates += n.handleMatrix(cloneFn, thisExists, thisChild, otherChild, addr, depth)
	}

	return duplicates
}

// UnionRecPersist is similar to unionRec but performs an immutable union of nodes.
func (n *_NODE_TYPE[V]) UnionRecPersist(cloneFn func(V) V, o *_NODE_TYPE[V], depth int) (duplicates int) {
	if cloneFn == nil {
		cloneFn = func(v V) V { return v }
	}

	// for all prefixes in other node do ...
	for oIdx := range o.Prefixes.All() {
		// clone/copy the value from other node
		val := o.MustGetPrefix(oIdx)
		clonedVal := cloneFn(val)

		// insert/overwrite cloned value from o into n
		if exists := n.InsertPrefix(oIdx, clonedVal); exists {
			// this prefix is duplicate in n and o
			duplicates++
		}
	}

	// for all child addrs in other node do ...
	i := 0
	for addr := range o.Children.All() {
		otherChild := o.Children.Items[i]
		thisChild, thisExists := n.GetChild(addr)

		// Use helper function to handle all 4x3 combinations
		duplicates += n.handleMatrixPersist(cloneFn, thisExists, thisChild, otherChild, addr, depth)

		i++
	}

	return duplicates
}

// handleMatrix, 12 possible combinations to union this child and other child
//
//	THIS,   OTHER: (always clone the other kid!)
//	--------------
//	NULL,   node    <-- insert node at addr
//	NULL,   leaf    <-- insert leaf at addr
//	NULL,   fringe  <-- insert fringe at addr
//
//	node,   node    <-- union rec-descent with node
//	node,   leaf    <-- insert leaf at depth+1
//	node,   fringe  <-- insert fringe at depth+1
//
//	leaf,   node    <-- insert new node, push this leaf down, union rec-descent
//	leaf,   leaf    <-- insert new node, push both leaves down (!first check equality)
//	leaf,   fringe  <-- insert new node, push this leaf and fringe down
//
//	fringe, node    <-- insert new node, push this fringe down, union rec-descent
//	fringe, leaf    <-- insert new node, push this fringe down, insert other leaf at depth+1
//	fringe, fringe  <-- just overwrite value
func (n *_NODE_TYPE[V]) handleMatrix(cloneFn func(V) V, thisExists bool, thisChild, otherChild any, addr uint8, depth int) int {
	// Do ALL type assertions upfront - reduces line noise
	var (
		thisNode, thisIsNode     = thisChild.(*_NODE_TYPE[V])
		thisLeaf, thisIsLeaf     = thisChild.(*LeafNode[V])
		thisFringe, thisIsFringe = thisChild.(*FringeNode[V])

		otherNode, otherIsNode     = otherChild.(*_NODE_TYPE[V])
		otherLeaf, otherIsLeaf     = otherChild.(*LeafNode[V])
		otherFringe, otherIsFringe = otherChild.(*FringeNode[V])
	)

	// just insert cloned child at this empty slot
	if !thisExists {
		switch {
		case otherIsNode:
			n.InsertChild(addr, otherNode.CloneRec(cloneFn))
		case otherIsLeaf:
			n.InsertChild(addr, &LeafNode[V]{Prefix: otherLeaf.Prefix, Value: cloneFn(otherLeaf.Value)})
		case otherIsFringe:
			n.InsertChild(addr, &FringeNode[V]{Value: cloneFn(otherFringe.Value)})
		default:
			panic("logic error, wrong node type")
		}
		return 0
	}

	// Case 1: Special cases that DON'T need a new node

	// Special case: fringe + fringe -> just overwrite value
	if thisIsFringe && otherIsFringe {
		thisFringe.Value = cloneFn(otherFringe.Value)
		return 1
	}

	// Special case: leaf + leaf with same prefix -> just overwrite value
	if thisIsLeaf && otherIsLeaf && thisLeaf.Prefix == otherLeaf.Prefix {
		thisLeaf.Value = cloneFn(otherLeaf.Value)
		return 1
	}

	// Case 2: thisChild is already a node - insert into it, no new node needed
	if thisIsNode {
		switch {
		case otherIsNode:
			return thisNode.UnionRec(cloneFn, otherNode, depth+1)
		case otherIsLeaf:
			if thisNode.Insert(otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
				return 1
			}
			return 0
		case otherIsFringe:
			if thisNode.InsertPrefix(1, cloneFn(otherFringe.Value)) {
				return 1
			}
			return 0
		default:
			panic("logic error, wrong node type")
		}
	}

	// Case 3: All remaining cases need a new node
	// (thisChild is leaf or fringe, and we didn't hit the special cases above)

	nc := new(_NODE_TYPE[V])

	// Push existing child down into new node
	switch {
	case thisIsLeaf:
		nc.Insert(thisLeaf.Prefix, thisLeaf.Value, depth+1)
	case thisIsFringe:
		nc.InsertPrefix(1, thisFringe.Value)
	default:
		panic("logic error, unexpected this child type")
	}

	// Replace child with new node
	n.InsertChild(addr, nc)

	// Now handle other child
	switch {
	case otherIsNode:
		return nc.UnionRec(cloneFn, otherNode, depth+1)
	case otherIsLeaf:
		if nc.Insert(otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
			return 1
		}
		return 0
	case otherIsFringe:
		if nc.InsertPrefix(1, cloneFn(otherFringe.Value)) {
			return 1
		}
		return 0
	default:
		panic("logic error, wrong other node type")
	}
}

// handleMatrixPersist, 12 possible combinations to union this child and other child
//
//	THIS,   OTHER: (always clone the other kid!)
//	--------------
//	NULL,   node    <-- insert node at addr
//	NULL,   leaf    <-- insert leaf at addr
//	NULL,   fringe  <-- insert fringe at addr
//
//	node,   node    <-- union rec-descent with node
//	node,   leaf    <-- insert leaf at depth+1
//	node,   fringe  <-- insert fringe at depth+1
//
//	leaf,   node    <-- insert new node, push this leaf down, union rec-descent
//	leaf,   leaf    <-- insert new node, push both leaves down (!first check equality)
//	leaf,   fringe  <-- insert new node, push this leaf and fringe down
//
//	fringe, node    <-- insert new node, push this fringe down, union rec-descent
//	fringe, leaf    <-- insert new node, push this fringe down, insert other leaf at depth+1
//	fringe, fringe  <-- just overwrite value
func (n *_NODE_TYPE[V]) handleMatrixPersist(cloneFn func(V) V, thisExists bool, thisChild, otherChild any, addr uint8, depth int) int {
	// Do ALL type assertions upfront - reduces line noise
	var (
		thisNode, thisIsNode     = thisChild.(*_NODE_TYPE[V])
		thisLeaf, thisIsLeaf     = thisChild.(*LeafNode[V])
		thisFringe, thisIsFringe = thisChild.(*FringeNode[V])

		otherNode, otherIsNode     = otherChild.(*_NODE_TYPE[V])
		otherLeaf, otherIsLeaf     = otherChild.(*LeafNode[V])
		otherFringe, otherIsFringe = otherChild.(*FringeNode[V])
	)

	// just insert cloned child at this empty slot
	if !thisExists {
		switch {
		case otherIsNode:
			n.InsertChild(addr, otherNode.CloneRec(cloneFn))
		case otherIsLeaf:
			n.InsertChild(addr, &LeafNode[V]{Prefix: otherLeaf.Prefix, Value: cloneFn(otherLeaf.Value)})
		case otherIsFringe:
			n.InsertChild(addr, &FringeNode[V]{Value: cloneFn(otherFringe.Value)})
		default:
			panic("logic error, wrong node type")
		}
		return 0
	}

	// Case 1: Special cases that DON'T need a new node

	// Special case: fringe + fringe -> just overwrite value
	if thisIsFringe && otherIsFringe {
		thisFringe.Value = cloneFn(otherFringe.Value)
		return 1
	}

	// Special case: leaf + leaf with same prefix -> just overwrite value
	if thisIsLeaf && otherIsLeaf && thisLeaf.Prefix == otherLeaf.Prefix {
		thisLeaf.Value = cloneFn(otherLeaf.Value)
		return 1
	}

	// Case 2: thisChild is already a node - clone this node, insert into it
	if thisIsNode {
		// CLONE the node

		// thisNode points now to cloned kid
		thisNode = thisNode.CloneFlat(cloneFn)

		// replace kid with cloned thisKid
		n.InsertChild(addr, thisNode)

		switch {
		case otherIsNode:
			return thisNode.UnionRecPersist(cloneFn, otherNode, depth+1)
		case otherIsLeaf:
			if thisNode.InsertPersist(cloneFn, otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
				return 1
			}
			return 0
		case otherIsFringe:
			if thisNode.InsertPrefix(1, cloneFn(otherFringe.Value)) {
				return 1
			}
			return 0
		default:
			panic("logic error, wrong node type")
		}
	}

	// Case 3: All remaining cases need a new node
	// (thisChild is leaf or fringe, and we didn't hit the special cases above)

	nc := new(_NODE_TYPE[V])

	// Push existing child down into new node
	switch {
	case thisIsLeaf:
		nc.Insert(thisLeaf.Prefix, thisLeaf.Value, depth+1)
	case thisIsFringe:
		nc.InsertPrefix(1, thisFringe.Value)
	default:
		panic("logic error, unexpected this child type")
	}

	// Replace child with new node
	n.InsertChild(addr, nc)

	// Now handle other child
	switch {
	case otherIsNode:
		return nc.UnionRec(cloneFn, otherNode, depth+1)
	case otherIsLeaf:
		if nc.Insert(otherLeaf.Prefix, cloneFn(otherLeaf.Value), depth+1) {
			return 1
		}
		return 0
	case otherIsFringe:
		if nc.InsertPrefix(1, cloneFn(otherFringe.Value)) {
			return 1
		}
		return 0
	default:
		panic("logic error, wrong other node type")
	}
}

// AllRec recursively traverses the trie starting at the current node,
// applying the provided yield function to every stored prefix and value.
//
// For each route entry (prefix and value), yield is invoked. If yield returns false,
// the traversal stops immediately, and false is propagated upwards,
// enabling early termination.
//
// The function handles all prefix entries in the current node, as well as any children -
// including sub-nodes, leaf nodes with full prefixes, and fringe nodes
// representing path-compressed prefixes. IP prefix reconstruction is performed on-the-fly
// from the current path and depth.
//
// The traversal order is not defined. This implementation favors simplicity
// and runtime efficiency over consistency of iteration sequence.
func (n *_NODE_TYPE[V]) AllRec(path StridePath, depth int, is4 bool, yield func(netip.Prefix, V) bool) bool {
	for idx := range n.Prefixes.All() {
		cidr := CidrFromPath(path, depth, is4, idx)
		val := n.MustGetPrefix(idx)

		// callback for this prefix and val
		if !yield(cidr, val) {
			// early exit
			return false
		}
	}

	// for all children (nodes and leaves) in this node do ...
	i := 0
	for addr := range n.Children.All() {
		anyKid := n.Children.Items[i]
		switch kid := anyKid.(type) {
		case *_NODE_TYPE[V]:
			// rec-descent with this node
			path[depth] = addr
			if !kid.AllRec(path, depth+1, is4, yield) {
				// early exit
				return false
			}
		case *LeafNode[V]:
			// callback for this leaf
			if !yield(kid.Prefix, kid.Value) {
				// early exit
				return false
			}
		case *FringeNode[V]:
			fringePfx := CidrForFringe(path[:], depth, is4, addr)
			// callback for this fringe
			if !yield(fringePfx, kid.Value) {
				// early exit
				return false
			}

		default:
			panic("logic error, wrong node type")
		}

		i++
	}

	return true
}

// AllRecSorted recursively traverses the trie in prefix-sorted order and applies
// the given yield function to each stored prefix and value.
//
// Unlike AllRec, this implementation ensures that route entries are visited in
// canonical prefix sort order. To achieve this,
// both the prefixes and children of the current node are gathered, sorted,
// and then interleaved during traversal based on logical octet positioning.
//
// The function first sorts relevant entries by their prefix index and address value,
// using a comparison function that ranks prefixes according to their mask length and position.
// Then it walks the trie, always yielding child entries that fall before the current prefix,
// followed by the prefix itself. Remaining children are processed once all prefixes have been visited.
//
// Prefixes are reconstructed on-the-fly from the traversal path, and iteration includes all child types:
// inner nodes (recursive descent), leaf nodes, and fringe (compressed) prefixes.
//
// The order is stable and predictable, making the function suitable for use cases
// like table exports, comparisons or serialization.
//
// Parameters:
//   - path: the current traversal path through the trie
//   - depth: current depth in the trie (0-based)
//   - is4: true for IPv4 processing, false for IPv6
//   - yield: callback function invoked for each prefix/value pair
//
// Returns false if yield function requests early termination.
func (n *_NODE_TYPE[V]) AllRecSorted(path StridePath, depth int, is4 bool, yield func(netip.Prefix, V) bool) bool {
	allIndices := n.Prefixes.AppendBits(make([]uint8, 0, n.PrefixCount()))
	allChildAddrs := n.Children.AppendBits(make([]uint8, 0, n.ChildCount()))

	// Sort local prefix indices into canonical CIDR rank order.
	slices.SortFunc(allIndices, CmpIndexRank)

	// Helper to process and yield any child node type (inner node, leaf, or fringe).
	yieldChild := func(addr uint8) bool {
		switch kid := n.MustGetChild(addr).(type) {
		case *_NODE_TYPE[V]:
			path[depth] = addr
			return kid.AllRecSorted(path, depth+1, is4, yield)

		case *LeafNode[V]:
			return yield(kid.Prefix, kid.Value)

		case *FringeNode[V]:
			fringePfx := CidrForFringe(path[:], depth, is4, addr)
			return yield(fringePfx, kid.Value)

		default:
			panic("logic error: unknown child node type")
		}
	}

	childCursor := 0

	// Interleave local prefixes and child subtrees in CIDR rank order.
	for _, pfxIdx := range allIndices {
		pfxOctet, _ := art.IdxToPfx(pfxIdx)

		// Yield all child subtrees whose base address precedes the current prefix octet.
		for childCursor < len(allChildAddrs) {
			childAddr := allChildAddrs[childCursor]
			if childAddr >= pfxOctet {
				break
			}

			if !yieldChild(childAddr) {
				return false
			}
			childCursor++
		}

		// Yield the local prefix for this index.
		cidr := CidrFromPath(path, depth, is4, pfxIdx)
		if !yield(cidr, n.MustGetPrefix(pfxIdx)) {
			return false
		}
	}

	// Yield remaining child subtrees strictly positioned after all local prefixes.
	for _, addr := range allChildAddrs[childCursor:] {
		if !yieldChild(addr) {
			return false
		}
	}

	return true
}

// EachLookupPrefix performs a hierarchical lookup of all matching prefixes
// in the current node’s 8-bit stride-based prefix table.
//
// The function walks up the trie-internal complete binary tree (CBT),
// testing each possible prefix length mask (in decreasing order of specificity),
// and invokes the yield function for every matching entry.
//
// The given idx refers to the position for this stride's prefix and is used
// to derive a backtracking path through the CBT by repeatedly halving the index.
// At each step, if a prefix exists in the table, its corresponding CIDR is
// reconstructed and yielded. If yield returns false, traversal stops early.
//
// This function is intended for internal use during supernet traversal and
// does not descend the trie further.
func (n *_NODE_TYPE[V]) EachLookupPrefix(ip netip.Addr, depth int, pfxIdx uint8, yield func(netip.Prefix, V) bool) (ok bool) {
	for ; pfxIdx > 0; pfxIdx >>= 1 {
		if n.Prefixes.Test(pfxIdx) {
			val := n.MustGetPrefix(pfxIdx)

			// get the CIDR back
			_, pfxLen := art.IdxToPfx(pfxIdx)
			cidr, _ := ip.Prefix(depth<<3 + int(pfxLen))

			if !yield(cidr, val) {
				return false
			}
		}
	}

	return true
}

// EachSubnet yields all routes and subtrees covered by pfxIdx within the current node
// in canonical CIDR sort order.
//
// It intersects the node's prefixes and child subtrees with precomputed lookup
// tables for pfxIdx. Covered prefixes are sorted by rank, and child subtrees are merged
// interleaved before and after prefixes based on their byte boundaries (pfxOctet).
//
// Subtrees are traversed recursively using AllRecSorted
// to guarantee deterministic ordering across stride boundaries.
//
// Expects the node to be at the path location specified by octets/depth.
func (n *_NODE_TYPE[V]) EachSubnet(octets []byte, depth int, is4 bool, pfxIdx uint8, yield func(netip.Prefix, V) bool) bool {
	// octets as array, needed below more than once
	var path StridePath
	copy(path[:], octets)

	var tmp bitset.BitSet256

	// bitset & node entries against precomputed allot tables for pfxIdx.
	tmp = n.Prefixes.And(&allot.PfxRoutesLookupTbl[pfxIdx])
	allCoveredIndices := tmp.AppendBits(make([]uint8, 0, tmp.OnesCount()))

	tmp = n.Children.And(&allot.FringeRoutesLookupTbl[pfxIdx])
	allCoveredChildAddrs := tmp.AppendBits(make([]uint8, 0, tmp.OnesCount()))

	// Sort covered prefix indices into canonical CIDR order.
	slices.SortFunc(allCoveredIndices, CmpIndexRank)

	// Helper to process and yield child entries (nodes, leaves, or fringes).
	yieldChild := func(addr uint8) bool {
		switch kid := n.MustGetChild(addr).(type) {
		case *_NODE_TYPE[V]:
			path[depth] = addr
			return kid.AllRecSorted(path, depth+1, is4, yield)

		case *LeafNode[V]:
			return yield(kid.Prefix, kid.Value)

		case *FringeNode[V]:
			fringePfx := CidrForFringe(path[:], depth, is4, addr)
			return yield(fringePfx, kid.Value)

		default:
			panic("logic error: unknown child node type")
		}
	}

	addrCursor := 0

	// Interleave local prefixes and child subtrees in CIDR rank order.
	for _, pfxIdx := range allCoveredIndices {
		pfxOctet, _ := art.IdxToPfx(pfxIdx)

		// Yield all child subtrees whose base address falls before the current prefix scope.
		for j := addrCursor; j < len(allCoveredChildAddrs); j++ {
			addr := allCoveredChildAddrs[j]
			if addr >= pfxOctet {
				break
			}

			if !yieldChild(addr) {
				return false
			}
			addrCursor++
		}

		// Yield the local prefix entry itself.
		cidr := CidrFromPath(path, depth, is4, pfxIdx)
		if !yield(cidr, n.MustGetPrefix(pfxIdx)) {
			return false
		}
	}

	// Yield remaining child subtrees strictly after all local prefixes.
	for _, addr := range allCoveredChildAddrs[addrCursor:] {
		if !yieldChild(addr) {
			return false
		}
	}

	return true
}

// Supernets yields all supernet prefixes of pfx that exist in the trie,
// in reverse order (most-specific first, least-specific last).
//
// It traverses upward from the given prefix toward the root, collecting
// matching prefixes along the path. The traversal uses a stack to yield
// results in reverse order, so that more-specific supernets appear before
// less-specific ones.
//
// The function handles all node types (internal nodes, leaves, and fringes)
// and stops early if the yield callback returns false.
//
// Parameters:
//   - pfx: The prefix for which to find supernets
//   - yield: Callback function invoked for each supernet prefix/value pair
//
// The yield function receives prefix/value pairs and returns false to stop
// the iteration early.
func (n *_NODE_TYPE[V]) Supernets(pfx netip.Prefix, yield func(netip.Prefix, V) bool) {
	ip := pfx.Addr()
	pfxLen := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// stack of the traversed nodes for reverse ordering of supernets
	stack := [MaxTreeDepth]*_NODE_TYPE[V]{}

	// run variable, used after for loop
	var depth int
	var octet byte

	// find last node along this octet path
LOOP:
	for depth, octet = range octets {
		// stepped one past the last stride of interest; back up to last and exit
		if depth > strideCount {
			depth--
			break
		}
		// push current node on stack
		stack[depth] = n

		// descend down the trie
		if !n.Children.Test(octet) {
			break LOOP
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			n = kid
			continue LOOP // descend down to next trie level

		case *LeafNode[V]:
			if kid.Prefix.Bits() > pfx.Bits() {
				break LOOP
			}

			if kid.Prefix.Overlaps(pfx) {
				if !yield(kid.Prefix, kid.Value) {
					// early exit
					return
				}
			}
			// end of trie along this octets path
			break LOOP

		case *FringeNode[V]:
			fringePfx := CidrForFringe(octets, depth, is4, octet)
			if fringePfx.Bits() > pfx.Bits() {
				break LOOP
			}

			if fringePfx.Overlaps(pfx) {
				if !yield(fringePfx, kid.Value) {
					// early exit
					return
				}
			}
			// end of trie along this octets path
			break LOOP

		default:
			panic("logic error, wrong node type")
		}
	}

	// start backtracking, unwind the stack
	for ; depth >= 0; depth-- {
		n = stack[depth]

		// only the lastOctet may have a different prefix len
		// all others are just host routes
		var idx uint8
		octet = octets[depth]
		// Last “octet” from prefix
		// Note: For /32 and /128, depth never reaches strideCount (4/16),
		if depth == strideCount {
			idx = art.PfxToIdx(octet, modBits)
		} else {
			idx = art.OctetToIdx(octet)
		}

		// micro benchmarking, skip if there is no match
		if !n.Contains(idx) {
			continue
		}

		// yield all the matching prefixes, not just the lpm
		if !n.EachLookupPrefix(ip, depth, idx, yield) {
			// early exit
			return
		}
	}
}

// Subnets yields all subnet prefixes covered by pfx that exist in the trie,
// in CIDR sort order.
//
// It first locates the trie node corresponding to pfx, then recursively
// yields all prefixes and child entries contained within that subtree.
// The traversal uses sorted iteration to maintain canonical CIDR ordering.
//
// The function handles various node types (internal nodes, leaves, and fringes)
// and uses EachSubnet and AllRecSorted for sorted traversal of covered prefixes.
//
// Parameters:
//   - pfx: The parent prefix whose subnets should be yielded
//   - yield: Callback function invoked for each subnet prefix/value pair
//
// The yield function receives prefix/value pairs and returns false to stop
// the iteration early. If pfx doesn't exist in the trie, no prefixes are yielded.
func (n *_NODE_TYPE[V]) Subnets(pfx netip.Prefix, yield func(netip.Prefix, V) bool) {
	// values derived from pfx
	ip := pfx.Addr()
	pfxLen := pfx.Bits()
	is4 := ip.Is4()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	// find the trie node
	for depth, octet := range octets {
		// Last “octet” from prefix
		// Note: For /32 and /128, depth never reaches strideCount (4/16),
		// so those are handled below via the fringe/leaf path.
		if depth == strideCount {
			idx := art.PfxToIdx(octet, modBits)
			n.EachSubnet(octets, depth, is4, idx, yield)
			return
		}

		if !n.Children.Test(octet) {
			return
		}
		kid := n.MustGetChild(octet)

		// kid is node or leaf or fringe at octet
		switch kid := kid.(type) {
		case *_NODE_TYPE[V]:
			n = kid
			continue // descend down to next trie level

		case *LeafNode[V]:
			if pfx.Bits() <= kid.Prefix.Bits() && pfx.Overlaps(kid.Prefix) {
				yield(kid.Prefix, kid.Value)
			}
			return // immediate return

		case *FringeNode[V]:
			// get the LPM prefix back from ip and depth
			// it's a fringe, bits are always /8, /16, /24, ...
			fringePfx, _ := ip.Prefix((depth + 1) << 3)

			if pfx.Bits() <= fringePfx.Bits() && pfx.Overlaps(fringePfx) {
				yield(fringePfx, kid.Value)
			}
			return // immediate return

		default:
			panic("logic error, wrong node type")
		}
	}
}

// Overlaps recursively compares two trie nodes and returns true
// if any of their prefixes or descendants overlap.
//
// The implementation checks for:
// 1. Direct overlapping prefixes on this node level
// 2. Prefixes in one node overlapping with children in the other
// 3. Matching child addresses in both nodes, which are recursively compared
//
// All 12 possible type combinations for child entries (node, leaf, fringe) are supported.
//
// The function is optimized for early exit on first match and uses heuristics to
// choose between set-based and loop-based matching for performance.
func (n *_NODE_TYPE[V]) Overlaps(o *_NODE_TYPE[V], depth int) bool {
	nPfxCount := n.PrefixCount()
	oPfxCount := o.PrefixCount()

	nChildCount := n.ChildCount()
	oChildCount := o.ChildCount()

	// ##############################
	// 1. Test if any routes overlaps
	// ##############################

	// full cross check
	if nPfxCount > 0 && oPfxCount > 0 {
		if n.OverlapsRoutes(o) {
			return true
		}
	}

	// ####################################
	// 2. Test if routes overlaps any child
	// ####################################

	// swap nodes to help chance on its way,
	// if the first call to expensive overlapsChildrenIn() is already true,
	// if both orders are false it doesn't help either
	if nChildCount > oChildCount {
		n, o = o, n

		nPfxCount = n.PrefixCount()
		oPfxCount = o.PrefixCount()

		nChildCount = n.ChildCount()
		oChildCount = o.ChildCount()
	}

	if nPfxCount > 0 && oChildCount > 0 {
		if n.OverlapsChildrenIn(o) {
			return true
		}
	}

	// symmetric reverse
	if oPfxCount > 0 && nChildCount > 0 {
		if o.OverlapsChildrenIn(n) {
			return true
		}
	}

	// ############################################
	// 3. children with same octet in nodes n and o
	// ############################################

	// stop condition, n or o have no children
	if nChildCount == 0 || oChildCount == 0 {
		return false
	}

	// stop condition, no child with identical octet in n and o
	if !n.Children.Overlaps(&o.Children.BitSet256) {
		return false
	}

	return n.OverlapsSameChildren(o, depth)
}

// OverlapsRoutes compares the prefix sets of two nodes (n and o).
//
// It first checks for direct bitset intersection (identical indices),
// then walks both prefix sets using the Contains method to detect if any
// of the n-prefixes is contained in o, or vice versa.
func (n *_NODE_TYPE[V]) OverlapsRoutes(o *_NODE_TYPE[V]) bool {
	// some prefixes are identical, trivial overlap
	if n.Prefixes.Overlaps(&o.Prefixes.BitSet256) {
		return true
	}

	// get the lowest idx (biggest prefix)
	nFirstIdx, _ := n.Prefixes.FirstSet()
	oFirstIdx, _ := o.Prefixes.FirstSet()

	// start with other min value
	nIdx := oFirstIdx
	oIdx := nFirstIdx

	nOK := true
	oOK := true

	// zip, range over n and o together to help chance on its way
	for nOK || oOK {
		if nOK {
			// does any route in o overlap this prefix from n
			if nIdx, nOK = n.Prefixes.NextSet(nIdx); nOK {
				if o.Contains(nIdx) {
					return true
				}

				if nIdx == 255 {
					// stop, don't overflow uint8!
					nOK = false
				} else {
					nIdx++
				}
			}
		}

		if oOK {
			// does any route in n overlap this prefix from o
			if oIdx, oOK = o.Prefixes.NextSet(oIdx); oOK {
				if n.Contains(oIdx) {
					return true
				}

				if oIdx == 255 {
					// stop, don't overflow uint8!
					oOK = false
				} else {
					oIdx++
				}
			}
		}
	}

	return false
}

// OverlapsChildrenIn checks whether the prefixes in node n
// overlap with any children (by address range) in node o.
//
// Uses bitset intersection or manual iteration heuristically,
// depending on prefix and child count.
//
// Bitset-based matching uses precomputed coverage tables
// to avoid per-address looping. This is critical for high fan-out nodes.
func (n *_NODE_TYPE[V]) OverlapsChildrenIn(o *_NODE_TYPE[V]) bool {
	pfxCount := n.PrefixCount()
	childCount := o.ChildCount()

	// heuristic: 15 is the crossover point where bitset operations become
	// more efficient than iteration, determined by micro benchmarks on typical
	// routing table distributions
	const overlapsRangeCutoff = 15

	doRange := childCount < overlapsRangeCutoff || pfxCount > overlapsRangeCutoff

	// do range over, not so many children and maybe too many prefixes for other algo below
	if doRange {
		for addr := range o.Children.All() {
			if n.Contains(art.OctetToIdx(addr)) {
				return true
			}
		}
		return false
	}

	// do bitset intersection, alloted route table with child octets
	// maybe too many children for range-over or not so many prefixes to
	// build the alloted routing table from them

	// use allot table with prefixes as bitsets, bitsets are precalculated.
	for idx := range n.Prefixes.All() {
		if o.Children.Overlaps(&allot.FringeRoutesLookupTbl[idx]) {
			return true
		}
	}

	return false
}

// OverlapsSameChildren compares all matching child addresses (octets)
// between node n and node o recursively.
//
// For each shared address, the corresponding child nodes (of any type)
// are compared using _NODE_TYPEOverlapsTwoChildren, which handles all
// node/leaf/fringe combinations.
func (n *_NODE_TYPE[V]) OverlapsSameChildren(o *_NODE_TYPE[V], depth int) bool {
	// intersect the child bitsets from n with o
	commonChildren := n.Children.And(&o.Children.BitSet256)

	for addr, ok := commonChildren.NextSet(0); ok; {
		nChild := n.MustGetChild(addr)
		oChild := o.MustGetChild(addr)

		if n.OverlapsTwoChildren(nChild, oChild, depth+1) {
			return true
		}

		if addr == 255 {
			break // Prevent uint8 overflow
		}

		addr, ok = commonChildren.NextSet(addr + 1)
	}
	return false
}

// OverlapsPrefixAtDepth returns true if any route in the subtree rooted at this node
// overlaps with the given pfx, starting the comparison at the specified depth.
//
// This function supports structural overlap detection even in compressed or sparse
// paths within the trie, including fringe and leaf nodes. Matching is directional:
// it returns true if a route fully covers pfx, or if pfx covers an existing route.
//
// At each step, it checks for visible prefixes and children that may intersect the
// target prefix via stride-based longest-prefix test. The walk terminates early as
// soon as a structural overlap is found.
//
// This function underlies the top-level OverlapsPrefix behavior and handles details of
// trie traversal across varying prefix lengths and compression levels.
func (n *_NODE_TYPE[V]) OverlapsPrefixAtDepth(pfx netip.Prefix, depth int) bool {
	ip := pfx.Addr()
	pfxLen := pfx.Bits()
	octets := ip.AsSlice()
	strideCount, modBits := DivMod8(pfxLen)

	for ; depth < len(octets); depth++ {
		if depth > strideCount {
			break
		}

		octet := octets[depth]

		// full octet path in node trie, check overlap with last prefix octet
		if depth == strideCount {
			return n.OverlapsIdx(art.PfxToIdx(octet, modBits))
		}

		// test if any route overlaps prefix´ so far
		// no best match needed, forward tests without backtracking
		if n.PrefixCount() != 0 && n.Contains(art.OctetToIdx(octet)) {
			return true
		}

		if !n.Children.Test(octet) {
			return false
		}

		// next child, node or leaf
		switch kid := n.MustGetChild(octet).(type) {
		case *_NODE_TYPE[V]:
			n = kid
			continue

		case *LeafNode[V]:
			return kid.Prefix.Overlaps(pfx)

		case *FringeNode[V]:
			return true

		default:
			panic("logic error, wrong node type")
		}
	}

	panic("unreachable: " + pfx.String())
}

// OverlapsIdx returns true if the given prefix index overlaps with any entry in this node.
//
// The overlap detection considers three categories:
//
//  1. Whether any stored prefix in this node covers the requested prefix (LPM test)
//  2. Whether the requested prefix covers any stored route in the node
//  3. Whether the requested prefix overlaps with any fringe or child entry
//
// Internally, it leverages precomputed bitsets from the allotment model,
// using fast bitwise set intersections instead of explicit range comparisons.
// This enables high-performance overlap checks on a single stride level
// without descending further into the trie.
func (n *_NODE_TYPE[V]) OverlapsIdx(idx uint8) bool {
	// 1. Test if any route in this node overlaps prefix?
	if n.Contains(idx) {
		return true
	}

	// 2. Test if prefix overlaps any route in this node
	if n.Prefixes.Overlaps(&allot.PfxRoutesLookupTbl[idx]) {
		return true
	}

	// 3. Test if prefix overlaps any child in this node
	return n.Children.Overlaps(&allot.FringeRoutesLookupTbl[idx])
}

// OverlapsTwoChildren handles all 3x3 combinations of
// node kinds (node, leaf, fringe).
//
//	3x3 possible different combinations for n and o
//
//	node, node    --> overlaps rec descent
//	node, leaf    --> overlapsPrefixAtDepth
//	node, fringe  --> true
//
//	leaf, node    --> overlapsPrefixAtDepth
//	leaf, leaf    --> netip.Prefix.Overlaps
//	leaf, fringe  --> true
//
//	fringe, node    --> true
//	fringe, leaf    --> true
//	fringe, fringe  --> true
func (n *_NODE_TYPE[V]) OverlapsTwoChildren(nChild, oChild any, depth int) bool {
	// child type detection
	nNode, nIsNode := nChild.(*_NODE_TYPE[V])
	nLeaf, nIsLeaf := nChild.(*LeafNode[V])
	_, nIsFringe := nChild.(*FringeNode[V])

	oNode, oIsNode := oChild.(*_NODE_TYPE[V])
	oLeaf, oIsLeaf := oChild.(*LeafNode[V])
	_, oIsFringe := oChild.(*FringeNode[V])

	// Handle all 9 combinations with a single expression
	switch {
	// NODE cases
	case nIsNode && oIsNode:
		return nNode.Overlaps(oNode, depth)
	case nIsNode && oIsLeaf:
		return nNode.OverlapsPrefixAtDepth(oLeaf.Prefix, depth)
	case nIsNode && oIsFringe:
		return true

	// LEAF cases
	case nIsLeaf && oIsNode:
		return oNode.OverlapsPrefixAtDepth(nLeaf.Prefix, depth)
	case nIsLeaf && oIsLeaf:
		return oLeaf.Prefix.Overlaps(nLeaf.Prefix)
	case nIsLeaf && oIsFringe:
		return true

	// FRINGE cases
	case nIsFringe:
		return true // fringe overlaps with everything

	default:
		panic("logic error, wrong node type combination")
	}
}

// CloneRec performs a recursive deep copy of the node and all its descendants.
//
// If cloneFn is nil, the stored values are copied directly without modification.
// Otherwise cloneFn is applied to each stored value for deep cloning.
//
// This method first creates a shallow clone of the current node using CloneFlat,
// applying cloneFn to values as described there. Then it recursively clones all
// child nodes of type *_NODE_TYPE[V], performing a full deep clone down the subtree.
//
// Child nodes of type *LeafNode[V] and *FringeNode[V] are already cloned
// by CloneFlat.
//
// Returns a new instance of _NODE_TYPE[V] which is a complete deep clone of the
// receiver node with all descendants.
func (n *_NODE_TYPE[V]) CloneRec(cloneFn func(V) V) *_NODE_TYPE[V] {
	if n == nil {
		return nil
	}

	// Perform a flat clone of the current node.
	c := n.CloneFlat(cloneFn)

	// Recursively clone all child nodes of type *_NODE_TYPE[V]
	for i, kidAny := range c.Children.Items {
		if kid, ok := kidAny.(*_NODE_TYPE[V]); ok {
			c.Children.Items[i] = kid.CloneRec(cloneFn)
		}
	}

	return c
}
