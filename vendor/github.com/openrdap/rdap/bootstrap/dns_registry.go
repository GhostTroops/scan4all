// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package bootstrap

import (
	"fmt"
	"net/url"
	"strings"
)

type DNSRegistry struct {
	// Map of domain labels (e.g. "br") to RDAP base URLs.
	dns map[string][]*url.URL

	file *File
}

// NewDNSRegistry creates a DNSRegistry from a DNS registry JSON document.
//
// The document format is specified in https://tools.ietf.org/html/rfc7484#section-4.
func NewDNSRegistry(json []byte) (*DNSRegistry, error) {
	var r *File
	r, err := NewFile(json)

	if err != nil {
		return nil, fmt.Errorf("Error parsing DNS bootstrap: %s", err)
	}

	return &DNSRegistry{
		dns:  r.Entries,
		file: r,
	}, nil
}

// Lookup returns the RDAP base URLs for the domain name question |question|.
func (d *DNSRegistry) Lookup(question *Question) (*Answer, error) {
	input := question.Query
	input = strings.TrimSuffix(input, ".")
	input = strings.ToLower(input)
	fqdn := input

	// Lookup the FQDN.
	// e.g. for an.example.com, the following lookups could occur:
	// - "an.example.com"
	// - "example.com"
	// - "com"
	// - "" (the root zone)
	var urls []*url.URL
	for {
		var ok bool
		urls, ok = d.dns[fqdn]

		if ok {
			break
		} else if fqdn == "" {
			break
		}

		index := strings.IndexByte(fqdn, '.')
		if index == -1 {
			fqdn = ""
		} else {
			fqdn = fqdn[index+1:]
		}
	}

	return &Answer{
		URLs:  urls,
		Query: input,
		Entry: fqdn,
	}, nil
}

// File returns a struct describing the registry's JSON document.
func (d *DNSRegistry) File() *File {
	return d.file
}
