// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// Entity represents information of an organisation or person.
//
// Entity is a topmost RDAP response object.
type Entity struct {
	DecodeData *DecodeData

	Common
	Conformance     []string `rdap:"rdapConformance"`
	ObjectClassName string
	Notices         []Notice

	Handle       string
	VCard        *VCard `rdap:"vcardArray"`
	Roles        []string
	PublicIDs    []PublicID `rdap:"publicIds"`
	Entities     []Entity
	Remarks      []Remark
	Links        []Link
	Events       []Event
	AsEventActor []Event
	Status       []string
	Port43       string
	Networks     []IPNetwork
	Autnums      []Autnum
}
