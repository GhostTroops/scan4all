// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package bootstrap

import (
	"fmt"
	"net/url"
	"strings"
)

type ServiceProviderRegistry struct {
	// Map of service tag (e.g. "VRSN") to RDAP base URLs.
	services map[string][]*url.URL

	// The registry's JSON document.
	file *File
}

// NewServiceProviderRegistry creates a ServiceProviderRegistry from a Service
// Provider JSON document.
//
// The document format is specified in
// https://datatracker.ietf.org/doc/draft-hollenbeck-regext-rdap-object-tag/.
func NewServiceProviderRegistry(json []byte) (*ServiceProviderRegistry, error) {
	var r *File
	r, err := NewFile(json)

	if err != nil {
		return nil, fmt.Errorf("Error parsing Service Provider bootstrap: %s", err)
	}

	return &ServiceProviderRegistry{
		services: r.Entries,
		file:     r,
	}, nil
}

// Lookup returns a list of RDAP base URLs for the entity question |question|.
//
// e.g. for the handle "53774930-VRSN", the RDAP base URLs for "VRSN" are returned.
//
// Missing/malformed/unknown service tags are not treated as errors. An empty
// list of URLs is returned in these cases.
//
// Deprecated: Previously service tags used a TILDE char (e.g. ~VRSN) instead,
// these are still supported.
func (s *ServiceProviderRegistry) Lookup(question *Question) (*Answer, error) {
	input := question.Query

	// Valid input looks like 12345-VRSN.
	offset := strings.LastIndexByte(input, '~')

	if offset == -1 {
		offset = strings.LastIndexByte(input, '-')
	}

	if offset == -1 || offset == len(input)-1 {
		return &Answer{
			Query: input,
		}, nil
	}

	service := input[offset+1:]

	urls, ok := s.services[service]

	if !ok {
		service = ""
	}

	return &Answer{
		URLs:  urls,
		Query: input,
		Entry: service,
	}, nil
}

// File returns a struct describing the registry's JSON document.
func (s *ServiceProviderRegistry) File() *File {
	return s.file
}
