// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package nodes

import (
	"cmp"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gaissmai/bart/internal/art"
)

// strideLen represents the byte stride length for the multibit trie.
// Each stride processes 8 bits (1 byte) at a time.
const strideLen = 8

// MaxItems defines the maximum number of prefixes or children that can be stored in a single node.
// This corresponds to 256 possible values for an 8-bit stride.
const MaxItems = 256

// MaxTreeDepth represents the maximum depth of the trie structure.
// For IPv6 addresses, this allows up to 16 bytes of depth.
const MaxTreeDepth = 16

// DepthMask is used for bounds check elimination (BCE) when accessing depth-indexed arrays.
const DepthMask = MaxTreeDepth - 1

// StridePath represents a path through the trie, with a maximum depth of 16 octets for IPv6.
type StridePath [MaxTreeDepth]uint8

// TrieItem, a node has no path information about its predecessors,
// we collect this during the recursive descent.
type TrieItem[V any] struct {
	// for traversing, Path/Depth/Idx is needed to get the CIDR back from the trie.
	Node  any // BartNode, FastNode, LiteNode
	Is4   bool
	Path  StridePath
	Depth int
	Idx   uint8

	// for printing
	Cidr netip.Prefix
	Val  V
}

// StatsT, only used for dump, tests and benchmarks
type StatsT struct {
	Prefixes int
	Children int
	SubNodes int
	Leaves   int
	Fringes  int
}

type nodeType byte

const (
	nullNode nodeType = iota // empty node
	fullNode                 // prefixes and children or path-compressed prefixes
	halfNode                 // no prefixes, only children and path-compressed prefixes
	pathNode                 // only children, no prefix nor path-compressed prefixes
	stopNode                 // no children, only prefixes or path-compressed prefixes
)

// String implements Stringer for nodeType.
func (nt nodeType) String() string {
	switch nt {
	case nullNode:
		return "NULL"
	case fullNode:
		return "FULL"
	case halfNode:
		return "HALF"
	case pathNode:
		return "PATH"
	case stopNode:
		return "STOP"
	default:
		return "unreachable"
	}
}

// addrFmt, different format strings for IPv4 and IPv6, decimal versus hex.
func addrFmt(addr byte, is4 bool) string {
	if is4 {
		return fmt.Sprintf("%d", addr)
	}

	return fmt.Sprintf("0x%02x", addr)
}

// ip stride path, different formats for IPv4 and IPv6, dotted decimal or hex.
//
//	127.0.0
//	2001:0d
func ipStridePath(path StridePath, depth int, is4 bool) string {
	buf := new(strings.Builder)

	if is4 {
		for i, b := range path[:depth] {
			if i != 0 {
				buf.WriteString(".")
			}

			buf.WriteString(strconv.Itoa(int(b)))
		}

		return buf.String()
	}

	for i, b := range path[:depth] {
		if i != 0 && i%2 == 0 {
			buf.WriteString(":")
		}

		fmt.Fprintf(buf, "%02x", b)
	}

	return buf.String()
}

// CmpPrefix, helper function, compare func for prefix sort,
// all cidrs are already normalized
func CmpPrefix(a, b netip.Prefix) int {
	if cmpAddr := a.Addr().Compare(b.Addr()); cmpAddr != 0 {
		return cmpAddr
	}

	return cmp.Compare(a.Bits(), b.Bits())
}

// LeafNode represents a path-compressed routing entry that stores both prefix and value.
// Leaf nodes are used when a prefix doesn't align with trie stride boundaries
// and needs to be stored as a compressed path to save memory.
type LeafNode[V any] struct {
	Value  V
	Prefix netip.Prefix
}

// NewLeafNode creates a new leaf node with the specified prefix and value.
func NewLeafNode[V any](pfx netip.Prefix, val V) *LeafNode[V] {
	return &LeafNode[V]{Prefix: pfx, Value: val}
}

// FringeNode represents a path-compressed routing entry that stores only a value.
// The prefix is implicitly defined by the node's position in the trie.
// Fringe nodes are used for prefixes that align exactly with stride boundaries
// (/8, /16, /24, etc.) to save memory by not storing redundant prefix information.
type FringeNode[V any] struct {
	Value V
}

// NewFringeNode creates a new fringe node with the specified value.
func NewFringeNode[V any](val V) *FringeNode[V] {
	return &FringeNode[V]{Value: val}
}

// IsFringe determines whether a prefix qualifies as a "FringeNode".
// Only prefixes that are stride-aligned (i.e., /8, /16, ..., /128)
// can be fringe-compressed. If these prefixes are inserted at a position
// where depth == (strideCount-1), they are treated as FringeNodes;
// at positions where depth < (strideCount-1), they are treated as LeafNodes.
//
// Example for a stride-aligned prefix like 192.168.1.0/24 (strideCount = 3, modBits = 0):
//
//	depth = 3,  depth == strideCount     : A direct prefix with 0/0 (default route for subtrie).
//	depth = 2,  depth == (strideCount-1) : A path-compressed fringe.
//	depth < 2,  depth  < (strideCount-1) : A path-compressed leaf.
func IsFringe(depth int, pfxLen int) bool {
	strideCount, modBits := DivMod8(pfxLen)
	return depth == strideCount-1 && modBits == 0
}

// CmpIndexRank, sort indexes in prefix sort order.
func CmpIndexRank(aIdx, bIdx uint8) int {
	// convert idx [1..255] to prefix
	aOctet, aBits := art.IdxToPfx(aIdx)
	bOctet, bBits := art.IdxToPfx(bIdx)

	// cmp the prefixes, first by address and then by bits
	if aOctet == bOctet {
		return cmp.Compare(aBits, bBits)
	}
	return cmp.Compare(aOctet, bOctet)
}

// CidrFromPath reconstructs a CIDR prefix from a stride path, depth, and index.
// The prefix is determined by the node's position in the trie and the base index
// from the ART algorithm's complete binary tree representation.
//
// Parameters:
//   - path: The stride path through the trie
//   - depth: Current depth in the trie
//   - is4: True for IPv4 processing, false for IPv6
//   - idx: The base index from the prefix table
//
// Returns the reconstructed netip.Prefix.
func CidrFromPath(path StridePath, depth int, is4 bool, idx uint8) netip.Prefix {
	depth &= DepthMask // BCE

	// retrieve the last octet and pfxLen
	octet, pfxLen := art.IdxToPfx(idx)

	// set byte in path at depth with last octet
	path[depth] = octet

	// canonicalize
	clear(path[depth+1:])

	// make ip addr from octets
	var ip netip.Addr
	if is4 {
		ip = netip.AddrFrom4([4]byte(path[:4]))
	} else {
		ip = netip.AddrFrom16(path)
	}

	// calc bits with pathLen and pfxLen
	bits := depth<<3 + int(pfxLen)

	// PrefixFrom does not allocate and does not mask off the host bits of ip.
	// With the clear(), the non-canonical bytes have already been removed.
	return netip.PrefixFrom(ip, bits)
}

// CidrForFringe reconstructs a CIDR prefix for a fringe node from the traversal path.
// Since fringe nodes don't store their prefix explicitly, it's derived entirely
// from the node's position in the trie and its final byte value.
//
// Parameters:
//   - octets:     The path of previous bytes leading up to the fringe.
//   - depth:      Current depth in the trie (which equals strideCount - 1).
//   - is4:        True for IPv4 processing, false for IPv6.
//   - fringeByte: The actual 8-bit value (0-255) of the prefix at this final stride.
//
// Returns the reconstructed netip.Prefix for the fringe.
func CidrForFringe(octets []byte, depth int, is4 bool, fringeByte uint8) netip.Prefix {
	depth &= DepthMask // BCE

	var path StridePath
	copy(path[:], octets)
	path[depth] = fringeByte

	// canonicalize, fringe bit boundaries are always a multiple of a byte
	clear(path[depth+1:])

	// make ip addr from octets
	var ip netip.Addr
	if is4 {
		ip = netip.AddrFrom4([4]byte(path[:4]))
	} else {
		ip = netip.AddrFrom16(path)
	}

	// it's a fringe, bits are always aligned on stride boundaries (/8, /16, /24, ...)
	bits := (depth + 1) << 3

	// PrefixFrom does not allocate and does not mask off the host bits of ip.
	// With the clear(), the non-canonical bytes have already been removed.
	return netip.PrefixFrom(ip, bits)
}

// DivMod8 returns the count of full 8‑bit strides (bits/8)
// and the remaining bits in the final stride (bits%8) for pfxLen.
//
// ATTENTION: Split the IP prefixes at 8-bit borders, count from 0.
//
//	/7, /15, /23, /31, ..., /127
//
//	BitPos: [0-7],[8-15],[16-23],[24-31],[32]
//	BitPos: [0-7],[8-15],[16-23],[24-31],[32-39],[40-47],[48-55],[56-63],...,[120-127],[128]
//
//	0.0.0.0/0      => strideCount:  0, modBits: 0 (default route)
//	0.0.0.0/7      => strideCount:  0, modBits: 7
//	0.0.0.0/8      => strideCount:  1, modBits: 0 (fringe candidate)
//	10.0.0.0/8     => strideCount:  1, modBits: 0 (fringe candidate)
//	10.0.0.0/22    => strideCount:  2, modBits: 6
//	10.0.0.0/29    => strideCount:  3, modBits: 5
//	10.0.0.0/32    => strideCount:  4, modBits: 0 (fringe candidate)
//
//	::/0           => strideCount:  0, modBits: 0 (default route)
//	::1/128        => strideCount: 16, modBits: 0 (fringe candidate)
//	2001:db8::/42  => strideCount:  5, modBits: 2
//	2001:db8::/56  => strideCount:  7, modBits: 0 (fringe candidate)
//
//	/32 and /128 prefixes are special, they never form a new node,
//	At the end of the trie (IPv4: depth 4, IPv6: depth 16) they are always
//	inserted as a path‑compressed fringe.
//
// We are not splitting at /8, /16, ..., because this would mean that the
// first node would have 512 prefixes, 9 bits from [0-8]. All remaining nodes
// would then only have 8 bits from [9-16], [17-24], [25..32], ...
// but the algorithm would then require a variable length bitset
// or imply a double-sized bitset.
//
// If you can commit to a fixed size of [4]uint64, then the algorithm is
// much faster due to modern CPUs.
func DivMod8(pfxLen int) (strideCount int, modBits uint8) {
	// strideCount: range from 0..4 or 0..16
	// modBits:     range from 0..7
	return pfxLen >> 3, uint8(pfxLen & 7)
}

// CloneLeaf creates and returns a copy of the leafNode receiver.
// If cloneFn is nil, the value is copied directly without modification.
// Otherwise, cloneFn is applied to the value for deep cloning.
// The prefix field is always copied as is.
func (l *LeafNode[V]) CloneLeaf(cloneFn func(V) V) *LeafNode[V] {
	if l == nil {
		return nil
	}

	if cloneFn == nil {
		return &LeafNode[V]{Prefix: l.Prefix, Value: l.Value}
	}
	return &LeafNode[V]{Prefix: l.Prefix, Value: cloneFn(l.Value)}
}

// CloneFringe creates and returns a copy of the FringeNode receiver.
// If cloneFn is nil, the value is copied directly without modification.
// Otherwise, cloneFn is applied to the value for deep cloning.
func (l *FringeNode[V]) CloneFringe(cloneFn func(V) V) *FringeNode[V] {
	if l == nil {
		return nil
	}

	if cloneFn == nil {
		return &FringeNode[V]{Value: l.Value}
	}
	return &FringeNode[V]{Value: cloneFn(l.Value)}
}
