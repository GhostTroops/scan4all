// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package bart

import (
	"sync"

	"github.com/gaissmai/bart/internal/nodes"
)

// Fast is similar to Table but uses additional 256 bytes in each node
// for faster level traversing in the multibit trie.
//
// As a result Fast sacrifices memory efficiency to achieve 25% better
// speed in lookup and contains.
//
// The zero value is ready to use.
//
// A Fast must not be copied by value; always pass by pointer.
// Nil pointers as receivers or arguments are forbidden and will panic.
//
// The Fast is safe for concurrent reads, but concurrent reads and writes
// must be externally synchronized. Mutation via Insert/Delete requires locks,
// or alternatively, use ...Persist methods which return a modified copy
// without altering the original table (copy-on-write).
//
// Performance note: Do not pass IPv4-in-IPv6 addresses (e.g., ::ffff:192.0.2.1)
// as input. The methods do not perform automatic unmapping to avoid unnecessary
// overhead for the common case where native addresses are used.
// Users should unmap IPv4-in-IPv6 addresses to their native IPv4 form
// (e.g., 192.0.2.1) before calling these methods.
type Fast[V any] struct {
	// used by -copylocks checker from `go vet`.
	_ [0]sync.Mutex

	// the root nodes, implemented as popcount compressed multibit tries
	root4 nodes.FastNode[V]
	root6 nodes.FastNode[V]

	// the number of prefixes in the routing table
	size4 int
	size6 int
}
