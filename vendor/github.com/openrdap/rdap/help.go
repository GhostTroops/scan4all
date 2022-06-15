// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// Help represents a help response.
//
// Help is a topmost RDAP response object.
type Help struct {
	DecodeData *DecodeData

	Common
	Conformance []string `rdap:"rdapConformance"`
	Notices     []Notice
}
