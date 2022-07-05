// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// DomainSearchResults represents a domain search response.
//
// DomainSearchResults is a topmost RDAP response object.
type DomainSearchResults struct {
	DecodeData *DecodeData

	Common
	Conformance []string `rdap:"rdapConformance"`
	Notices     []Notice

	Domains []Domain `rdap:"domainSearchResults"`
}

// NameserverSearchResults represents a nameserver search response.
//
// NameserverSearchResults is a topmost RDAP response object.
type NameserverSearchResults struct {
	DecodeData *DecodeData

	Common
	Conformance []string `rdap:"rdapConformance"`
	Notices     []Notice

	Nameservers []Nameserver `rdap:"nameserverSearchResults"`
}

// EntitySearchResults represents an entity search response.
//
// EntitySearchResults is a topmost RDAP response object.
type EntitySearchResults struct {
	DecodeData *DecodeData

	Common
	Conformance []string `rdap:"rdapConformance"`
	Notices     []Notice

	Entities []Entity `rdap:"entitySearchResults"`
}
