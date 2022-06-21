// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

type NetRegistry struct {
	// Map of netmask size (0-32 for IPv4, 0-128 for IPv6) to list of NetEntries.
	networks map[int][]netEntry

	numIPBytes int // Length in bytes of each IP address (4 for IPv4, 16 for IPv6).

	file *File
}

// A netEntry is a network and its RDAP base URLs.
type netEntry struct {
	Net  *net.IPNet
	URLs []*url.URL
}

type netEntrySorter []netEntry

func (a netEntrySorter) Len() int {
	return len(a)
}

func (a netEntrySorter) Swap(i int, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a netEntrySorter) Less(i int, j int) bool {
	return bytes.Compare(a[i].Net.IP, a[j].Net.IP) <= 0
}

// NewNetRegistry creates a NetRegistry from an IPv4 or IPv6 registry JSON document. ipVersion must be 4 or 6.
//
// The document formats are specified in https://tools.ietf.org/html/rfc7484#section-5.1 and https://tools.ietf.org/html/rfc7484#section-5.2.
func NewNetRegistry(json []byte, ipVersion int) (*NetRegistry, error) {
	if ipVersion != 4 && ipVersion != 6 {
		return nil, fmt.Errorf("Unknown IP version %d", ipVersion)
	}

	var registry *File
	registry, err := NewFile(json)

	if err != nil {
		return nil, fmt.Errorf("Error parsing net registry file: %s", err)
	}

	n := &NetRegistry{
		networks:   map[int][]netEntry{},
		numIPBytes: numIPBytesForVersion(ipVersion),
		file:       registry,
	}

	var cidr string
	var urls []*url.URL
	for cidr, urls = range registry.Entries {
		_, ipNet, err := net.ParseCIDR(cidr)

		if err != nil {
			continue
		} else if len(ipNet.IP) != n.numIPBytes {
			continue
		}

		size, _ := ipNet.Mask.Size()
		n.networks[size] = append(n.networks[size], netEntry{Net: ipNet, URLs: urls})
	}

	for _, nets := range n.networks {
		sort.Sort(netEntrySorter(nets))
	}

	return n, nil
}

// Lookup returns the RDAP base URLs for the IP address or CIDR range question |Question|.
//
// Example queries are: "192.0.2.0", "192.0.2.0/25". "2001:db8::", "2001::db8::/62".
func (n *NetRegistry) Lookup(question *Question) (*Answer, error) {
	input := question.Query

	if !strings.ContainsAny(input, "/") {
		// Convert IP address to CIDR format, with a /32 or /128 mask.
		input = fmt.Sprintf("%s/%d", input, n.numIPBytes*8)
	}

	_, lookupNet, err := net.ParseCIDR(input)

	if err != nil {
		return nil, err
	}

	if len(lookupNet.IP) != n.numIPBytes {
		return nil, errors.New("Lookup address has wrong IP protocol")
	}

	lookupMask, _ := lookupNet.Mask.Size()

	var bestEntry string
	var bestURLs []*url.URL
	var bestMask int

	var mask int
	var nets []netEntry
	for mask, nets = range n.networks {
		if mask < bestMask || mask > lookupMask {
			continue
		}

		index := sort.Search(len(nets), func(i int) bool {
			net := nets[i].Net
			return net.Contains(lookupNet.IP) || bytes.Compare(net.IP, lookupNet.IP) >= 0
		})

		if index == len(nets) || !nets[index].Net.Contains(lookupNet.IP) {
			continue
		}

		bestEntry = nets[index].Net.String()
		bestMask = mask
		bestURLs = nets[index].URLs
	}

	return &Answer{
		Query: input,
		Entry: bestEntry,
		URLs:  bestURLs,
	}, nil
}

func numIPBytesForVersion(ipVersion int) int {
	len := 0

	switch ipVersion {
	case 4:
		len = net.IPv4len
	case 6:
		len = net.IPv6len
	default:
		panic("Unknown IP version")
	}

	return len
}

// File returns a struct describing the registry's JSON document.
func (n *NetRegistry) File() *File {
	return n.file
}
