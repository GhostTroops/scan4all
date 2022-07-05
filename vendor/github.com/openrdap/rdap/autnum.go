// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// Autnum represents information of Autonomous System registrations.
//
// Autnum is a topmost RDAP response object.
type Autnum struct {
	DecodeData *DecodeData

	Common
	Conformance     []string `rdap:"rdapConformance"`
	ObjectClassName string
	Notices         []Notice

	Handle      string
	StartAutnum *uint32
	EndAutnum   *uint32
	IPVersion   string `rdap:"ipVersion"`
	Name        string
	Type        string
	Status      []string
	Country     string
	Entities    []Entity
	Remarks     []Remark
	Links       []Link
	Port43      string
	Events      []Event
}
