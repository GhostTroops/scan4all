//go:build generate

// Copyright (c) 2026 Karl Gaissmaier
// SPDX-License-Identifier: MIT

//go:generate ../../scripts/generate-node-tests.sh

package nodes

// ### GENERATE DELETE START ###

// stub code for generator types and methods
// useful for gopls during development, deleted during go generate

import (
	"bytes"
	"io"
	"iter"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/gaissmai/bart/internal/tests/golden"
	"github.com/gaissmai/bart/internal/tests/random"
	"github.com/gaissmai/bart/internal/value"
)

type _NODE_TYPE[V any] struct{}

func (n *_NODE_TYPE[V]) StatsRec() (_ StatsT)                                              { return }
func (n *_NODE_TYPE[V]) dump(io.Writer, StridePath, int, bool)                             { return }
func (n *_NODE_TYPE[V]) DumpRec(io.Writer, StridePath, int, bool)                          { return }
func (n *_NODE_TYPE[V]) FprintRec(io.Writer, TrieItem[V], string) (_ error)                { return }
func (n *_NODE_TYPE[V]) Insert(netip.Prefix, V, int) (_ bool)                              { return }
func (n *_NODE_TYPE[V]) Delete(netip.Prefix) (_ bool)                                      { return }
func (n *_NODE_TYPE[V]) InsertPersist(func(V) V, netip.Prefix, V, int) (_ bool)            { return }
func (n *_NODE_TYPE[V]) DeletePersist(func(V) V, netip.Prefix) (_ bool)                    { return }
func (n *_NODE_TYPE[V]) Subnets(netip.Prefix, func(netip.Prefix, V) bool)                  { return }
func (n *_NODE_TYPE[V]) Supernets(netip.Prefix, func(netip.Prefix, V) bool)                { return }
func (n *_NODE_TYPE[V]) AllRec(StridePath, int, bool, func(netip.Prefix, V) bool) (_ bool) { return }

func (n *_NODE_TYPE[V]) AllRecSorted(StridePath, int, bool, func(netip.Prefix, V) bool) (_ bool) {
	return
}

// ### GENERATE DELETE END ###

// helpers
func (n *_NODE_TYPE[V]) all4() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if n == nil {
			return
		}
		_ = n.AllRec(StridePath{}, 0, true, yield)
	}
}

func (n *_NODE_TYPE[V]) all6() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if n == nil {
			return
		}
		_ = n.AllRec(StridePath{}, 0, false, yield)
	}
}

func (n *_NODE_TYPE[V]) allSorted4() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if n == nil {
			return
		}
		_ = n.AllRecSorted(StridePath{}, 0, true, yield)
	}
}

func (n *_NODE_TYPE[V]) allSorted6() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if n == nil {
			return
		}
		_ = n.AllRecSorted(StridePath{}, 0, false, yield)
	}
}

func TestInsertDelete__NODE_TYPE(t *testing.T) {
	t.Parallel()

	zero := 0

	testsInsertDelete := []struct {
		name        string
		pfxs        []string
		is4         bool
		wantPfxs    int
		wantLeaves  int
		wantFringes int
	}{
		{
			name:        "null",
			pfxs:        []string{},
			is4:         true,
			wantPfxs:    0,
			wantLeaves:  0,
			wantFringes: 0,
		},
		{
			name:        "one prefix in root node",
			pfxs:        []string{"0.0.0.0/0"},
			is4:         true,
			wantPfxs:    1,
			wantLeaves:  0,
			wantFringes: 0,
		},
		{
			name:        "one prefix in root node IPv6",
			pfxs:        []string{"::/0"},
			is4:         false,
			wantPfxs:    1,
			wantLeaves:  0,
			wantFringes: 0,
		},
		{
			name:        "one leaf in root node",
			pfxs:        []string{"0.0.0.0/32"},
			is4:         true,
			wantPfxs:    0,
			wantLeaves:  1,
			wantFringes: 0,
		},
		{
			name:        "one leaf in root node IPv6",
			pfxs:        []string{"::/32"},
			is4:         false,
			wantPfxs:    0,
			wantLeaves:  1,
			wantFringes: 0,
		},
		{
			name:        "one fringe in root node",
			pfxs:        []string{"0.0.0.0/8"},
			is4:         true,
			wantPfxs:    0,
			wantLeaves:  0,
			wantFringes: 1,
		},
		{
			name:        "one fringe in root node IPv6",
			pfxs:        []string{"0::/8"},
			is4:         false,
			wantPfxs:    0,
			wantLeaves:  0,
			wantFringes: 1,
		},
		{
			name:        "many pfxs in root node",
			pfxs:        []string{"0.0.0.0/0", "0.0.0.0/1", "0.0.0.0/2", "0.0.0.0/3"},
			is4:         true,
			wantPfxs:    4,
			wantLeaves:  0,
			wantFringes: 0,
		},
		{
			name:        "many pfxs in root node IPv6",
			pfxs:        []string{"::/0", "::/1", "::/2", "::/3"},
			is4:         false,
			wantPfxs:    4,
			wantLeaves:  0,
			wantFringes: 0,
		},
		{
			name: "many pfxs and leaves in root node",
			pfxs: []string{
				"0.0.0.0/0", "0.0.0.0/1", "0.0.0.0/2", "0.0.0.0/3", // pfxs
				"0.0.0.0/9", "1.0.0.0/9", "2.0.0.0/9", "3.0.0.0/9", // leaves
			},
			is4:         true,
			wantPfxs:    4,
			wantLeaves:  4,
			wantFringes: 0,
		},
		{
			name: "many pfxs and leaves in root node IPv6",
			pfxs: []string{
				"::/0", "::/1", "::/2", "::/3", // pfxs
				"::/9", "0100::/9", "0200::/9", "0300::/9", // leaves
			},
			is4:         false,
			wantPfxs:    4,
			wantLeaves:  4,
			wantFringes: 0,
		},
		{
			name: "many pfxs, leaves and fringes in root node",
			pfxs: []string{
				"0.0.0.0/0", "0.0.0.0/1", // pfxs
				"0.0.0.0/9", "1.0.0.0/19", "2.0.0.0/29", // leaves
				"4.0.0.0/8", "5.0.0.0/8", "6.0.0.0/8", "7.0.0.0/8", // fringes
			},
			is4:         true,
			wantPfxs:    2,
			wantLeaves:  3,
			wantFringes: 4,
		},
		{
			name: "many pfxs, leaves and fringes in root node IPv6",
			pfxs: []string{
				"::/0", "::/1", // pfxs
				"::/9", "0100::/19", "0200::/29", // leaves
				"0400::/8", "0500::/8", "0600::/8", "0700::/8", // fringes
			},
			is4:         false,
			wantPfxs:    2,
			wantLeaves:  3,
			wantFringes: 4,
		},
		{
			name: "many pfxs, leaves and fringes in deeper level",
			pfxs: []string{
				"0.0.0.0/9", "0.0.0.0/10", // pfxs in level 1
				"0.1.0.0/19", // leaf in level 1
				"0.2.0.0/16", // fringe in level 1
			},
			is4:         true,
			wantPfxs:    2,
			wantLeaves:  1,
			wantFringes: 1,
		},
		{
			name: "many pfxs, leaves and fringes in deeper level IPv6",
			pfxs: []string{
				"::/9", "::/10", // pfxs in level 1
				"0010::/19", // leaf in level 1
				"0020::/16", // fringe in level 1
			},
			is4:         false,
			wantPfxs:    2,
			wantLeaves:  1,
			wantFringes: 1,
		},
		{
			name: "leaves and fringes in deeper level",
			pfxs: []string{
				"0.0.0.0/12", // pfx in level 1
				"0.0.0.0/16", // fringe in level 1 -> default pfx in level 2
				"0.0.0.0/24", // fringe in level 2
			},
			is4:         true,
			wantPfxs:    2,
			wantLeaves:  0,
			wantFringes: 1,
		},
		{
			name: "leaves and fringes in deeper level IPv6",
			pfxs: []string{
				"::/12", // pfx in level 1
				"::/16", // fringe in level 1 -> default pfx in level 2
				"::/24", // fringe in level 2
			},
			is4:         false,
			wantPfxs:    2,
			wantLeaves:  0,
			wantFringes: 1,
		},
	}

	for _, tt := range testsInsertDelete {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			n := new(_NODE_TYPE[int])
			for _, s := range tt.pfxs {
				n.Insert(mpp(s), zero, 0)
				n.Insert(mpp(s), zero, 0) // idempotent
			}

			stats := n.StatsRec()
			if pfxs := stats.Prefixes; pfxs != tt.wantPfxs {
				t.Errorf("after insert: got num pfxs %d, want %d", pfxs, tt.wantPfxs)
			}
			if leaves := stats.Leaves; leaves != tt.wantLeaves {
				t.Errorf("after insert: got num leaves %d, want %d", leaves, tt.wantLeaves)
			}
			if fringes := stats.Fringes; fringes != tt.wantFringes {
				t.Errorf("after insert: got num fringes %d, want %d", fringes, tt.wantFringes)
			}

			if t.Failed() {
				buf := new(strings.Builder)
				n.DumpRec(buf, StridePath{}, 0, tt.is4)
				t.Logf("%s:\n%s", tt.name, buf.String())
			}

			// delete all prefixes

			for _, s := range tt.pfxs {
				n.Delete(mpp(s))
				n.Delete(mpp(s)) // idempotent
			}

			stats = n.StatsRec()
			if num := stats.Prefixes; num != 0 {
				t.Errorf("after delete: got num pfxs %d, want 0", num)
			}
			if num := stats.Leaves; num != 0 {
				t.Errorf("after delete: got num leaves %d, want 0", num)
			}
			if num := stats.Fringes; num != 0 {
				t.Errorf("after delete: got num fringes %d, want 0", num)
			}

			if t.Failed() {
				buf := new(strings.Builder)
				n.DumpRec(buf, StridePath{}, 0, tt.is4)
				t.Logf("%s:\n%s", tt.name, buf.String())
			}
		})

		t.Run("Persist_"+tt.name, func(t *testing.T) {
			t.Parallel()

			n := new(_NODE_TYPE[int])

			for _, s := range tt.pfxs {
				n.InsertPersist(nil, mpp(s), zero, 0)
				n.InsertPersist(nil, mpp(s), zero, 0) // idempotent
			}

			stats := n.StatsRec()
			if pfxs := stats.Prefixes; pfxs != tt.wantPfxs {
				t.Errorf("after insert: got num pfxs %d, want %d", pfxs, tt.wantPfxs)
			}
			if leaves := stats.Leaves; leaves != tt.wantLeaves {
				t.Errorf("after insert: got num leaves %d, want %d", leaves, tt.wantLeaves)
			}
			if fringes := stats.Fringes; fringes != tt.wantFringes {
				t.Errorf("after insert: got num fringes %d, want %d", fringes, tt.wantFringes)
			}

			if t.Failed() {
				buf := new(strings.Builder)
				n.DumpRec(buf, StridePath{}, 0, tt.is4)
				t.Logf("%s:\n%s", tt.name, buf.String())
			}

			// delete all prefixes

			for _, s := range tt.pfxs {
				n.DeletePersist(nil, mpp(s))
				n.DeletePersist(nil, mpp(s)) // idempotent
			}

			stats = n.StatsRec()
			if num := stats.Prefixes; num != 0 {
				t.Errorf("after delete: got num pfxs %d, want 0", num)
			}
			if num := stats.Leaves; num != 0 {
				t.Errorf("after delete: got num leaves %d, want 0", num)
			}
			if num := stats.Fringes; num != 0 {
				t.Errorf("after delete: got num fringes %d, want 0", num)
			}

			if t.Failed() {
				buf := new(strings.Builder)
				n.DumpRec(buf, StridePath{}, 0, tt.is4)
				t.Logf("%s:\n%s", tt.name, buf.String())
			}
		})
	}
}

func TestAllIterators__NODE_TYPE(t *testing.T) {
	t.Parallel()
	n := workLoadN()

	prng := rand.New(rand.NewPCG(42, 42))

	for range 10 {
		pfxs := random.RealWorldPrefixes4(prng, n)

		node := new(_NODE_TYPE[int])
		for _, p := range pfxs {
			node.Insert(p, 0, 0)
		}

		// AllRec: collect without order guarantee
		var got []netip.Prefix
		i := 0
		for p := range node.all4() {
			i++
			got = append(got, p)
			if i >= n/2 {
				break
			}
		}

		if len(got) != n/2 {
			t.Fatalf("AllRec len=%d, want %d", len(got), n/2)
		}

		got = nil
		i = 0
		for p := range node.allSorted4() {
			i++
			got = append(got, p)
			if i >= n/2 {
				break
			}
		}

		if len(got) != n/2 {
			t.Fatalf("AllRecSorted len=%d, want %d", len(got), n/2)
		}

		slices.SortFunc(pfxs, CmpPrefix)
		if !slices.Equal(pfxs[:n/2], got) {
			t.Fatal("AllRecSorted is not as expected")
		}
	}
}

func TestSupernets4__NODE_TYPE(t *testing.T) {
	t.Parallel()
	n := workLoadN()
	prng := rand.New(rand.NewPCG(42, 42))

	for range 10 {
		pfxs := random.RealWorldPrefixes4(prng, n)

		node := new(_NODE_TYPE[int])
		gold := new(golden.Table[int])

		for i, pfx := range pfxs {
			node.Insert(pfx, i, 0)
			gold.Insert(pfx, i)
		}

		// test with random probes
		for _, probe := range pfxs {
			goldSupernets := gold.Supernets(probe)
			nodeSupernets := []netip.Prefix{}

			node.Supernets(probe, func(p netip.Prefix, _ int) bool {
				nodeSupernets = append(nodeSupernets, p)
				return true
			})

			if !slices.Equal(goldSupernets, nodeSupernets) {
				t.Errorf("Supernets expected equal to golden implementation")
			}
		}
	}
}

func TestSupernets6__NODE_TYPE(t *testing.T) {
	t.Parallel()
	n := workLoadN()
	prng := rand.New(rand.NewPCG(42, 42))

	for range 10 {
		pfxs := random.RealWorldPrefixes6(prng, n)

		node := new(_NODE_TYPE[int])
		gold := new(golden.Table[int])

		for i, pfx := range pfxs {
			node.Insert(pfx, i, 0)
			gold.Insert(pfx, i)
		}

		// test with random probes
		for _, probe := range pfxs {
			goldSupernets := gold.Supernets(probe)
			nodeSupernets := []netip.Prefix{}

			node.Supernets(probe, func(p netip.Prefix, _ int) bool {
				nodeSupernets = append(nodeSupernets, p)
				return true
			})

			if !slices.Equal(goldSupernets, nodeSupernets) {
				t.Errorf("Supernets expected equal to golden implementation")
			}
		}
	}
}

func TestSubnets4__NODE_TYPE(t *testing.T) {
	t.Parallel()
	n := workLoadN()
	prng := rand.New(rand.NewPCG(42, 42))

	for range 10 {
		pfxs := random.RealWorldPrefixes4(prng, n)

		node := new(_NODE_TYPE[int])
		gold := new(golden.Table[int])

		for i, pfx := range pfxs {
			node.Insert(pfx, i, 0)
			gold.Insert(pfx, i)
		}

		// the default route must have all pfxs as subnet
		defaultRoute := mpp("0.0.0.0/0")
		allPfxsSorted := slices.Clone(pfxs)
		slices.SortFunc(allPfxsSorted, CmpPrefix)

		nodeSubnets := []netip.Prefix{}
		node.Subnets(defaultRoute, func(p netip.Prefix, _ int) bool {
			nodeSubnets = append(nodeSubnets, p)
			return true
		})

		if !slices.Equal(allPfxsSorted, nodeSubnets) {
			t.Errorf("Subnets(%s) not equal to all sorted prefixes", defaultRoute)
		}

		kMax := max(1, n/10)
		somePfxs := make([]netip.Prefix, 0, kMax) // allocate mem 1x

		for k := range kMax {
			somePfxs = somePfxs[:0] // reset slice

			i := 0
			node.Subnets(defaultRoute, func(p netip.Prefix, _ int) bool {
				if i >= k {
					// early-termination: stop after k
					return false
				}
				i++
				somePfxs = append(somePfxs, p)
				return true
			})

			if len(somePfxs) != k {
				t.Errorf("Subnets early-termination: got %d items, want %d", len(somePfxs), k)
			}

			if !slices.Equal(somePfxs, allPfxsSorted[:k]) {
				t.Errorf("Subnets expected equal")
			}
		}

		// test with random probes
		for _, probe := range pfxs {
			goldSubnets := gold.Subnets(probe)
			nodeSubnets := []netip.Prefix{}

			node.Subnets(probe, func(p netip.Prefix, _ int) bool {
				nodeSubnets = append(nodeSubnets, p)
				return true
			})

			if !slices.Equal(goldSubnets, nodeSubnets) {
				t.Errorf("Subnets expected equal to golden implementation")
			}
		}
	}
}

func TestSubnets6__NODE_TYPE(t *testing.T) {
	t.Parallel()
	n := workLoadN()
	prng := rand.New(rand.NewPCG(42, 42))

	for range 10 {
		pfxs := random.RealWorldPrefixes6(prng, n)

		node := new(_NODE_TYPE[int])
		gold := new(golden.Table[int])

		for i, pfx := range pfxs {
			node.Insert(pfx, i, 0)
			gold.Insert(pfx, i)
		}

		// the default route must have all pfxs as subnet
		defaultRoute := mpp("::/0")
		allPfxsSorted := slices.Clone(pfxs)
		slices.SortFunc(allPfxsSorted, CmpPrefix)

		nodeSubnets := []netip.Prefix{}
		node.Subnets(defaultRoute, func(p netip.Prefix, _ int) bool {
			nodeSubnets = append(nodeSubnets, p)
			return true
		})

		if !slices.Equal(allPfxsSorted, nodeSubnets) {
			t.Errorf("Subnets(%s) not equal to all sorted prefixes", defaultRoute)
		}

		kMax := max(1, n/10)
		somePfxs := make([]netip.Prefix, 0, kMax) // allocate mem 1x

		for k := range kMax {
			somePfxs = somePfxs[:0] // reset slice

			i := 0
			node.Subnets(defaultRoute, func(p netip.Prefix, _ int) bool {
				if i >= k {
					// early-termination: stop after k
					return false
				}
				i++
				somePfxs = append(somePfxs, p)
				return true
			})

			if len(somePfxs) != k {
				t.Errorf("Subnets early-termination: got %d items, want %d", len(somePfxs), k)
			}

			if !slices.Equal(somePfxs, allPfxsSorted[:k]) {
				t.Errorf("Subnets expected equal")
			}
		}

		// test with random probes
		for _, probe := range pfxs {
			goldSubnets := gold.Subnets(probe)
			nodeSubnets := []netip.Prefix{}

			node.Subnets(probe, func(p netip.Prefix, _ int) bool {
				nodeSubnets = append(nodeSubnets, p)
				return true
			})

			if !slices.Equal(goldSubnets, nodeSubnets) {
				t.Errorf("Subnets expected equal to golden implementation")
			}
		}
	}
}

// TestDump_EMPTY_STRUCT verifies that dump does not print values when V is a empty struct type.
func TestDump_EMPTY_STRUCT__NODE_TYPE(t *testing.T) {
	t.Parallel()

	node := new(_NODE_TYPE[struct{}])

	// Insert prefix to populate the node
	pfx := mpp("10.0.0.0/7")
	node.Insert(pfx, struct{}{}, 0)

	var buf strings.Builder
	path := StridePath{}
	node.dump(&buf, path, 0, true)

	output := buf.String()

	// For EMPTY_STRUCT, dump should print prefixes(#N) but skip the "values(#N):" section
	if !strings.Contains(output, "prefxs(") {
		t.Errorf("Expected 'prefxs()' section, but not found in:\n%s", output)
	}

	// For EMPTY_STRUCT, dump should print prefxs(#N) but skip the "values(#N):" section
	if strings.Contains(output, "values(") {
		t.Errorf("Expected no 'values()' section for EMPTY_STRUCT, but found it in:\n%s", output)
	}
}

// TestDump_NonEMPTY_STRUCT verifies that dump prints values when V is not a empty struct type.
func TestDump_NonEMPTY_STRUCT__NODE_TYPE(t *testing.T) {
	t.Parallel()

	node := new(_NODE_TYPE[int])

	// Skip for LiteNode (no real payload)
	if _, isLite := any(node).(*LiteNode[int]); isLite {
		t.Skip("LiteNode has no real payload")
	}

	pfx := mpp("10.0.0.0/7")
	node.Insert(pfx, 42, 0)

	var buf strings.Builder
	path := StridePath{}
	node.dump(&buf, path, 0, true)

	output := buf.String()

	// dump should include the "prefxs(#N):" section
	if !strings.Contains(output, "prefxs(") {
		t.Errorf("Expected 'prefxs()' section, but not found in:\n%s", output)
	}

	// For non-EMPTY_STRUCT, dump should include the "values(#N):" section
	if !strings.Contains(output, "values(") {
		t.Errorf("Expected 'values()' section for non-EMPTY_STRUCT, but not found in:\n%s", output)
	}

	// Should contain the actual value
	if !strings.Contains(output, "42") {
		t.Errorf("Expected value '42' in output, but not found in:\n%s", output)
	}
}

// TestFprintRec_EMPTY_STRUCT verifies FprintRec does not print values for empty struct types.
func TestFprintRec_EMPTY_STRUCT__NODE_TYPE(t *testing.T) {
	t.Parallel()

	node := new(_NODE_TYPE[struct{}])

	pfx := mpp("10.0.0.0/7")
	node.Insert(pfx, struct{}{}, 0)

	parent := TrieItem[struct{}]{
		Node:  nil,
		Is4:   true,
		Path:  StridePath{},
		Depth: 0,
		Idx:   0,
		Cidr:  mpp("0.0.0.0/0"),
	}

	var buf bytes.Buffer
	if err := node.FprintRec(&buf, parent, ""); err != nil {
		t.Fatalf("FprintRec failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, pfx.String()) {
		t.Errorf("Expected '%s' in output, got:\n%s", pfx, output)
	}

	// For EMPTY_STRUCT, output should show prefix but no value in parentheses
	if strings.Contains(output, "10.0.0.0/7 (") || strings.Contains(output, "10.0.0.0/7(") {
		t.Errorf("Expected no value in parentheses for EMPTY_STRUCT prefix, but found in:\n%s", output)
	}
}

// TestFprintRec_NonEMPTY_STRUCT verifies FprintRec prints values for non-empty struct types.
func TestFprintRec_NonEMPTY_STRUCT__NODE_TYPE(t *testing.T) {
	t.Parallel()

	node := new(_NODE_TYPE[string])

	// Skip for LiteNode (no real payload)
	if _, isLite := any(node).(*LiteNode[string]); isLite {
		t.Skip("LiteNode has no real payload")
	}

	pfx := mpp("10.0.0.0/7")
	node.Insert(pfx, "testval", 0)

	parent := TrieItem[string]{
		Node:  nil,
		Is4:   true,
		Path:  StridePath{},
		Depth: 0,
		Idx:   0,
		Cidr:  mpp("0.0.0.0/0"),
		Val:   "Default Gateway",
	}

	var buf bytes.Buffer

	if err := node.FprintRec(&buf, parent, ""); err != nil {
		t.Fatalf("FprintRec failed: %v", err)
	}

	output := buf.String()

	// For non-EMPTY_STRUCT, output should show both prefix and value
	if !strings.Contains(output, "10.0.0.0/7") || !strings.Contains(output, "testval") {
		t.Errorf("Expected prefix and value 'testval' in output, but got:\n%s", output)
	}
}

// TestEqualRec__NODE_TYPE tests the recursive node equality comparison.
func TestEqualRec__NODE_TYPE(t *testing.T) {
	t.Parallel()

	// nil checks
	var nilNode1, nilNode2 *_NODE_TYPE[int]
	if !nilNode1.EqualRec(nilNode2) {
		t.Error("nil nodes should be equal")
	}

	n1 := new(_NODE_TYPE[int])
	if n1.EqualRec(nilNode1) {
		t.Error("non-nil node should not be equal to nil")
	}
	if nilNode1.EqualRec(n1) {
		t.Error("nil node should not be equal to non-nil")
	}

	// identical nodes
	if !n1.EqualRec(n1) {
		t.Error("node should be equal to itself")
	}

	// different prefix bitsets
	n2 := new(_NODE_TYPE[int])
	n1.Insert(mpp("10.0.0.0/7"), 42, 0)
	if n1.EqualRec(n2) {
		t.Error("nodes with different prefixes should not be equal")
	}

	// different values
	// Skip for LiteNode because it has no real payload values
	if _, isLite := any(n1).(*LiteNode[int]); !isLite {
		n2.Insert(mpp("10.0.0.0/7"), 43, 0)
		if n1.EqualRec(n2) {
			t.Error("nodes with same prefixes but different values should not be equal")
		}
	}

	// same prefix and value
	n2_same := new(_NODE_TYPE[int])
	n2_same.Insert(mpp("10.0.0.0/7"), 42, 0)
	if _, isLite := any(n1).(*LiteNode[int]); !isLite {
		if !n1.EqualRec(n2_same) {
			t.Error("nodes with same prefixes and values should be equal")
		}
	}

	// different children bitsets
	n3 := new(_NODE_TYPE[int])
	n4 := new(_NODE_TYPE[int])
	n3.Insert(mpp("10.0.0.0/8"), 42, 0) // this is a fringe node at depth 1, and inserts into Children
	if n3.EqualRec(n4) {
		t.Error("nodes with different children should not be equal")
	}

	// fringe nodes with different values
	if _, isLite := any(n3).(*LiteNode[int]); !isLite {
		n4.Insert(mpp("10.0.0.0/8"), 43, 0)
		if n3.EqualRec(n4) {
			t.Error("nodes with different fringe values should not be equal")
		}
	}

	// leaf nodes with different prefixes/values
	n5 := new(_NODE_TYPE[int])
	n6 := new(_NODE_TYPE[int])
	n5.Insert(mpp("10.20.0.0/15"), 42, 0) // leaf node at depth 1
	n6.Insert(mpp("10.30.0.0/15"), 42, 0) // different leaf node prefix
	if n5.EqualRec(n6) {
		t.Error("nodes with different leaf prefixes should not be equal")
	}

	if _, isLite := any(n5).(*LiteNode[int]); !isLite {
		n7 := new(_NODE_TYPE[int])
		n7.Insert(mpp("10.20.0.0/15"), 43, 0) // different leaf value
		if n5.EqualRec(n7) {
			t.Error("nodes with different leaf values should not be equal")
		}
	}
}

// TestOverlapsExtra__NODE_TYPE tests specific edge cases in trie overlap detection.
func TestOverlapsExtra__NODE_TYPE(t *testing.T) {
	t.Parallel()

	// 1. Test OverlapsSameChildren loop continuation & completion (returning false)
	t.Run("same_children_no_overlap", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		// Insert disjoint child subnets at address 10 and 20
		n1.Insert(mpp("10.10.1.0/24"), 42, 0)
		n1.Insert(mpp("10.20.1.0/24"), 42, 0)

		n2.Insert(mpp("10.10.2.0/24"), 42, 0)
		n2.Insert(mpp("10.20.2.0/24"), 42, 0)

		if n1.Overlaps(n2, 0) {
			t.Error("expected no overlap between disjoint child subnets")
		}
	})

	// 2. Test OverlapsSameChildren loop continuation & early exit (returning true)
	t.Run("same_children_first_no_overlap_second_overlap", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		// Address 10 does not overlap, address 20 does overlap
		n1.Insert(mpp("10.10.1.0/24"), 42, 0)
		n1.Insert(mpp("10.20.1.0/24"), 42, 0)

		n2.Insert(mpp("10.10.2.0/24"), 42, 0)
		n2.Insert(mpp("10.20.1.0/24"), 42, 0) // overlap here

		if !n1.Overlaps(n2, 0) {
			t.Error("expected overlap since second child subnet overlaps")
		}
	})

	// 3. Test OverlapsSameChildren with matching child at address 255 that does not overlap
	t.Run("same_children_boundary_255_no_overlap", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		n1.Insert(mpp("10.255.1.0/24"), 42, 0)
		n2.Insert(mpp("10.255.2.0/24"), 42, 0)

		if n1.Overlaps(n2, 0) {
			t.Error("expected no overlap on boundary 255")
		}
	})

	// 4. Test OverlapsPrefixAtDepth with LeafNode and FringeNode
	t.Run("prefix_overlaps_leaf_node_true", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n1.Insert(mpp("10.20.0.0/15"), 42, 0)

		if !n1.OverlapsPrefixAtDepth(mpp("10.20.0.0/16"), 0) {
			t.Error("expected overlap with leaf node prefix")
		}
	})

	t.Run("prefix_overlaps_leaf_node_false", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n1.Insert(mpp("10.20.0.0/15"), 42, 0)

		if n1.OverlapsPrefixAtDepth(mpp("10.30.0.0/16"), 0) {
			t.Error("expected no overlap with disjoint prefix")
		}
	})

	t.Run("prefix_overlaps_fringe_node", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n1.Insert(mpp("10.0.0.0/8"), 42, 0)

		if !n1.OverlapsPrefixAtDepth(mpp("10.0.0.0/16"), 0) {
			t.Error("expected overlap with fringe node")
		}
	})

	// 5. Test OverlapsPrefixAtDepth with deeper path walk
	t.Run("prefix_overlaps_idx_at_last_octet", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n1.Insert(mpp("10.20.30.0/24"), 42, 0)

		if !n1.OverlapsPrefixAtDepth(mpp("10.20.0.0/16"), 0) {
			t.Error("expected overlap at last octet")
		}
	})

	t.Run("prefix_overlaps_contains_at_depth", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n1.Insert(mpp("10.128.30.0/24"), 42, 0)
		n1.Insert(mpp("10.128.0.0/9"), 42, 0)

		if !n1.OverlapsPrefixAtDepth(mpp("10.128.30.0/24"), 0) {
			t.Error("expected overlap with contains check at depth 1")
		}
	})
}

// TestDumpStringExtra__NODE_TYPE tests type classification in DumpString and DumpRec.
func TestDumpStringExtra__NODE_TYPE(t *testing.T) {
	t.Parallel()

	// 1. Create a halfNode at the root
	n1 := new(_NODE_TYPE[int])
	// LeafNode under child slot 10:
	n1.Insert(mpp("10.20.0.0/15"), 42, 0)
	// Internal node under child slot 11 (requires branching to prevent path compression):
	n1.Insert(mpp("11.30.40.0/24"), 42, 0)
	n1.Insert(mpp("11.30.50.0/24"), 42, 0)

	dump1 := n1.DumpString(nil, 0, true)
	if !strings.Contains(dump1, "HALF") {
		t.Errorf("expected HALF node type in dump, got:\n%s", dump1)
	}

	// 2. Create a pathNode at the root
	n2 := new(_NODE_TYPE[int])
	// Branching paths under child slot 10 to create an internal node at root child 10
	n2.Insert(mpp("10.20.30.0/24"), 42, 0)
	n2.Insert(mpp("10.20.40.0/24"), 42, 0)

	dump2 := n2.DumpString(nil, 0, true)
	if !strings.Contains(dump2, "PATH") {
		t.Errorf("expected PATH node type in dump, got:\n%s", dump2)
	}

	// 3. Test DumpRec on nil/empty node
	var nilNode *_NODE_TYPE[int]
	var buf bytes.Buffer
	nilNode.DumpRec(&buf, StridePath{}, 0, true)
	if buf.Len() != 0 {
		t.Error("expected empty buffer for nil DumpRec")
	}

	buf.Reset()
	emptyNode := new(_NODE_TYPE[int])
	emptyNode.DumpRec(&buf, StridePath{}, 0, true)
	if buf.Len() != 0 {
		t.Error("expected empty buffer for empty DumpRec")
	}
}

// TestDeletePurgeExtra__NODE_TYPE tests the bottom-up trie compression on delete.
func TestDeletePurgeExtra__NODE_TYPE(t *testing.T) {
	t.Parallel()

	// 1. Trigger PurgeAndCompress: case childCount == 1 with LeafNode
	t.Run("purge_leaf_node", func(t *testing.T) {
		t.Parallel()
		n := new(_NODE_TYPE[int])
		n.Insert(mpp("10.20.10.0/24"), 42, 0)
		n.Insert(mpp("10.20.20.0/24"), 42, 0)

		n.Delete(mpp("10.20.20.0/24"))

		if _, ok := n.Get(mpp("10.20.10.0/24")); !ok {
			t.Error("expected remaining leaf node to be present")
		}
	})

	// 2. Trigger PurgeAndCompress: case childCount == 1 with FringeNode
	t.Run("purge_fringe_node", func(t *testing.T) {
		t.Parallel()
		n := new(_NODE_TYPE[int])
		n.Insert(mpp("10.20.0.0/16"), 42, 0)
		n.Insert(mpp("10.30.0.0/16"), 42, 0)

		n.Delete(mpp("10.30.0.0/16"))

		if _, ok := n.Get(mpp("10.20.0.0/16")); !ok {
			t.Error("expected remaining fringe node to be present")
		}
	})

	// 3. Trigger PurgeAndCompress: case pfxCount == 1
	t.Run("purge_single_prefix", func(t *testing.T) {
		t.Parallel()
		n := new(_NODE_TYPE[int])
		n.Insert(mpp("10.20.0.0/16"), 42, 0)
		n.Insert(mpp("10.0.0.0/8"), 42, 0)

		n.Delete(mpp("10.20.0.0/16"))

		if _, ok := n.Get(mpp("10.0.0.0/8")); !ok {
			t.Error("expected remaining prefix to be present")
		}
	})
}

// TestUnionRecExtra__NODE_TYPE tests specific edge cases in trie Union operations.
func TestUnionRecExtra__NODE_TYPE(t *testing.T) {
	t.Parallel()

	_, isLite := any(new(_NODE_TYPE[int])).(*LiteNode[int])

	// 1. Cover handleMatrix case 2: thisIsNode && otherIsLeaf, where leaf already exists in thisNode
	t.Run("node_leaf_exists", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		// Both n1 and n2 have child at octet 10, but:
		// n1's child is an internal node (requires branching to prevent path compression)
		n1.Insert(mpp("10.10.10.0/24"), 42, 0)
		n1.Insert(mpp("10.10.20.0/24"), 42, 0)

		// n2's child is a LeafNode with "10.10.20.0/24"
		n2.Insert(mpp("10.10.20.0/24"), 43, 0)

		n1.UnionRec(value.CloneFnFactory[int](), n2, 0)

		val, ok := n1.Get(mpp("10.10.20.0/24"))
		if !ok {
			t.Fatal("expected prefix to exist")
		}
		if !isLite && val != 43 {
			t.Errorf("expected value 43, got %v", val)
		}
	})

	// 2. Cover handleMatrix case 2: thisIsNode && otherIsFringe, where fringe already exists in thisNode
	t.Run("node_fringe_exists", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		// Both n1 and n2 have child at octet 10.
		// n1's child is an internal node and contains the default route/fringe "10.0.0.0/8"
		n1.Insert(mpp("10.10.10.0/24"), 42, 0)
		n1.Insert(mpp("10.0.0.0/8"), 42, 0)

		// n2's child is a FringeNode "10.0.0.0/8"
		n2.Insert(mpp("10.0.0.0/8"), 43, 0)

		n1.UnionRec(value.CloneFnFactory[int](), n2, 0)

		val, ok := n1.Get(mpp("10.0.0.0/8"))
		if !ok {
			t.Fatal("expected prefix to exist")
		}
		if !isLite && val != 43 {
			t.Errorf("expected value 43, got %v", val)
		}
	})

	// 3. Cover handleMatrixPersist case 2 counterpart
	t.Run("node_leaf_exists_persist", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		n1.Insert(mpp("10.10.10.0/24"), 42, 0)
		n1.Insert(mpp("10.10.20.0/24"), 42, 0)

		n2.Insert(mpp("10.10.20.0/24"), 43, 0)

		n1.UnionRecPersist(value.CloneFnFactory[int](), n2, 0)

		val, ok := n1.Get(mpp("10.10.20.0/24"))
		if !ok {
			t.Fatal("expected prefix to exist")
		}
		if !isLite && val != 43 {
			t.Errorf("expected value 43, got %v", val)
		}
	})

	t.Run("node_fringe_exists_persist", func(t *testing.T) {
		t.Parallel()
		n1 := new(_NODE_TYPE[int])
		n2 := new(_NODE_TYPE[int])

		n1.Insert(mpp("10.10.10.0/24"), 42, 0)
		n1.Insert(mpp("10.0.0.0/8"), 42, 0)

		n2.Insert(mpp("10.0.0.0/8"), 43, 0)

		n1.UnionRecPersist(value.CloneFnFactory[int](), n2, 0)

		val, ok := n1.Get(mpp("10.0.0.0/8"))
		if !ok {
			t.Fatal("expected prefix to exist")
		}
		if !isLite && val != 43 {
			t.Errorf("expected value 43, got %v", val)
		}
	})
}

// TestSubnetsEarlyExit__NODE_TYPE tests early termination in Subnets traversal.
func TestSubnetsEarlyExit__NODE_TYPE(t *testing.T) {
	t.Parallel()

	n := new(_NODE_TYPE[int])
	n.Insert(mpp("10.0.0.0/8"), 1, 0)
	n.Insert(mpp("10.10.10.0/24"), 2, 0)
	n.Insert(mpp("10.10.20.0/24"), 3, 0)
	n.Insert(mpp("10.20.0.0/15"), 4, 0)

	// Traversal 1: yield returns false immediately
	yieldCount := 0
	n.Subnets(mpp("10.0.0.0/8"), func(pfx netip.Prefix, val int) bool {
		yieldCount++
		return false // stop immediately
	})

	if yieldCount != 1 {
		t.Errorf("expected yieldCount to be 1, got %d", yieldCount)
	}

	// Traversal 2: yield returns false after 2 items
	yieldCount = 0
	n.Subnets(mpp("10.0.0.0/8"), func(pfx netip.Prefix, val int) bool {
		yieldCount++
		if yieldCount == 2 {
			return false
		}
		return true
	})

	if yieldCount != 2 {
		t.Errorf("expected yieldCount to be 2, got %d", yieldCount)
	}
}

// TestSupernetsExtra__NODE_TYPE tests specific edge cases and early exits in Supernets traversal.
func TestSupernetsExtra__NODE_TYPE(t *testing.T) {
	t.Parallel()

	n := new(_NODE_TYPE[int])
	// LeafNode at depth 1:
	n.Insert(mpp("10.20.0.0/15"), 1, 0)
	// FringeNode at depth 1:
	n.Insert(mpp("10.30.0.0/16"), 2, 0)
	// Normal prefixes:
	n.Insert(mpp("10.0.0.0/8"), 3, 0)
	n.Insert(mpp("10.40.50.0/24"), 4, 0)

	// 1. LeafNode longer prefix check
	yielded := []netip.Prefix{}
	n.Supernets(mpp("10.20.0.0/15"), func(pfx netip.Prefix, val int) bool {
		yielded = append(yielded, pfx)
		return true
	})
	if len(yielded) != 2 {
		t.Errorf("expected 2 supernets, got %v", yielded)
	}

	// 2. FringeNode longer prefix check
	yielded = []netip.Prefix{}
	n.Supernets(mpp("10.30.0.0/16"), func(pfx netip.Prefix, val int) bool {
		yielded = append(yielded, pfx)
		return true
	})
	if len(yielded) != 2 {
		t.Errorf("expected 2 supernets, got %v", yielded)
	}

	// 3. Early exits on yield
	// LeafNode yield false
	yieldCount := 0
	n.Supernets(mpp("10.20.0.0/15"), func(pfx netip.Prefix, val int) bool {
		yieldCount++
		if pfx == mpp("10.20.0.0/15") {
			return false
		}
		return true
	})
	if yieldCount != 1 {
		t.Errorf("expected yieldCount 1 on leaf early exit, got %d", yieldCount)
	}

	// FringeNode yield false
	yieldCount = 0
	n.Supernets(mpp("10.30.0.0/16"), func(pfx netip.Prefix, val int) bool {
		yieldCount++
		if pfx == mpp("10.30.0.0/16") {
			return false
		}
		return true
	})
	if yieldCount != 1 {
		t.Errorf("expected yieldCount 1 on fringe early exit, got %d", yieldCount)
	}

	// Backtracking yield false
	yieldCount = 0
	n.Supernets(mpp("10.40.50.0/24"), func(pfx netip.Prefix, val int) bool {
		yieldCount++
		return false
	})
	if yieldCount != 1 {
		t.Errorf("expected yieldCount 1 on backtracking early exit, got %d", yieldCount)
	}

	// 4. Trigger depth > strideCount
	yielded = []netip.Prefix{}
	n.Supernets(mpp("10.40.0.0/16"), func(pfx netip.Prefix, val int) bool {
		yielded = append(yielded, pfx)
		return true
	})
	if len(yielded) != 1 || yielded[0] != mpp("10.0.0.0/8") {
		t.Errorf("expected only 10.0.0.0/8, got %v", yielded)
	}
}
