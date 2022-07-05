// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// Nameserver represents information of a DNS nameserver.
//
// Nameserver is a topmost RDAP response object.
type Nameserver struct {
	DecodeData *DecodeData

	Common
	Conformance     []string `rdap:"rdapConformance"`
	ObjectClassName string
	Notices         []Notice

	Handle      string
	LDHName     string `rdap:"ldhName"`
	UnicodeName string

	IPAddresses *IPAddressSet `rdap:"ipAddresses"`

	Entities []Entity
	Status   []string
	Remarks  []Remark
	Links    []Link
	Port43   string
	Events   []Event
}

// IPAddressSet is a subfield of Nameserver.
type IPAddressSet struct {
	DecodeData *DecodeData

	Common
	V6 []string
	V4 []string
}
