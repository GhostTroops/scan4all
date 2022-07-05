// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// Error represents an error response.
//
// Error is a topmost RDAP response object.
type Error struct {
	DecodeData *DecodeData

	Common
	Conformance []string `rdap:"rdapConformance"`

	Notices []Notice

	ErrorCode   *uint16
	Title       string
	Description []string
}
