// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package bootstrap

import "net/url"

// Answer represents the result of bootstrapping a single query.
type Answer struct {
	// Query looked up in the registry.
	//
	// This includes any canonicalisation performed to match the Service
	// Registry's data format. e.g. lowercasing of domain names, and removal of
	// "AS" from AS numbers.
	Query string

	// Matching service entry. Empty string if no match.
	Entry string

	// List of RDAP base URLs.
	URLs []*url.URL
}
