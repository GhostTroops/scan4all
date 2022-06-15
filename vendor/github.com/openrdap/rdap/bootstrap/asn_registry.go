// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package bootstrap

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type ASNRegistry struct {
	// List of ASNs & their RDAP base URLs.
	//
	// Stored in a sorted order for fast search.
	asns []asnRange

	file *File
}

// asnRange represents a range of AS numbers and their RDAP base URLs.
//
// Represents a single AS number when MinASN==MaxASN.
type asnRange struct {
	MinASN uint32     // First AS number.
	MaxASN uint32     // Last AS number.
	URLs   []*url.URL // RDAP base URLs.
}

// String returns "ASxxxx" for a single AS, or "ASxxxx-ASyyyy" for a range.
func (a asnRange) String() string {
	if a.MinASN == a.MaxASN {
		return fmt.Sprintf("AS%d", a.MinASN)
	}

	return fmt.Sprintf("AS%d-AS%d", a.MinASN, a.MaxASN)
}

type asnRangeSorter []asnRange

func (a asnRangeSorter) Len() int {
	return len(a)
}

func (a asnRangeSorter) Swap(i int, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a asnRangeSorter) Less(i int, j int) bool {
	return a[i].MinASN < a[j].MinASN
}

// NewASNRegistry creates an ASNRegistry from an ASN registry JSON document.
//
// The document format is specified in https://tools.ietf.org/html/rfc7484#section-5.3.
func NewASNRegistry(json []byte) (*ASNRegistry, error) {
	var registry *File
	registry, err := NewFile(json)

	if err != nil {
		return nil, fmt.Errorf("Error parsing ASN registry: %s\n", err)
	}

	a := make([]asnRange, 0, len(registry.Entries))

	var asn string
	var urls []*url.URL
	for asn, urls = range registry.Entries {
		minASN, maxASN, err := parseASNRange(asn)

		if err != nil {
			continue
		}

		a = append(a, asnRange{MinASN: minASN, MaxASN: maxASN, URLs: urls})
	}

	sort.Sort(asnRangeSorter(a))

	return &ASNRegistry{
		asns: a,
		file: registry,
	}, nil
}

// Lookup returns the RDAP base URLs for the AS number question |question|.
//
// Example queries are: "AS1234", "as1234", and "1234".
func (a *ASNRegistry) Lookup(question *Question) (*Answer, error) {
	var asn uint32
	asn, err := parseASN(question.Query)

	if err != nil {
		return nil, err
	}

	index := sort.Search(len(a.asns), func(i int) bool {
		return asn <= a.asns[i].MaxASN
	})

	var entry string
	var urls []*url.URL

	if index != len(a.asns) && (asn >= a.asns[index].MinASN && asn <= a.asns[index].MaxASN) {
		entry = a.asns[index].String()
		urls = a.asns[index].URLs
	}

	return &Answer{
		Query: fmt.Sprintf("%d", asn),
		Entry: entry,
		URLs:  urls,
	}, nil
}

// File returns a struct describing the registry's JSON document.
func (a *ASNRegistry) File() *File {
	return a.file
}

func parseASN(asn string) (uint32, error) {
	asn = strings.ToLower(asn)
	asn = strings.TrimLeft(asn, "as")
	result, err := strconv.ParseUint(asn, 10, 32)

	if err != nil {
		return 0, err
	}

	return uint32(result), nil
}

func parseASNRange(asnRange string) (uint32, uint32, error) {
	var minASN uint64
	var maxASN uint64
	var err error

	asns := strings.Split(asnRange, "-")

	if len(asns) != 1 && len(asns) != 2 {
		return 0, 0, errors.New("Malformed ASN range")
	}

	minASN, err = strconv.ParseUint(asns[0], 10, 32)
	if err != nil {
		return 0, 0, err
	}

	if len(asns) == 2 {
		maxASN, err = strconv.ParseUint(asns[1], 10, 32)
		if err != nil {
			return 0, 0, err
		}
	} else {
		maxASN = minASN
	}

	if minASN > maxASN {
		minASN, maxASN = maxASN, minASN
	}

	return uint32(minASN), uint32(maxASN), nil
}
