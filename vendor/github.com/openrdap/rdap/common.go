// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// RDAP Conformance
// Appears in topmost JSON objects only, embedded (no separate type):
// Conformance []string `rdap:"rdapConformance"`
//
// https://tools.ietf.org/html/rfc7483#section-4.1

// Link signifies a link another resource on the Internet.
//
// https://tools.ietf.org/html/rfc7483#section-4.2
type Link struct {
	DecodeData *DecodeData

	Value    string
	Rel      string
	Href     string
	HrefLang []string `rdap:"hreflang"`
	Title    string
	Media    string
	Type     string
}

// Notice contains information about the entire RDAP response.
//
// https://tools.ietf.org/html/rfc7483#section-4.3
type Notice struct {
	DecodeData *DecodeData

	Title       string
	Type        string
	Description []string
	Links       []Link
}

// Remark contains information about the containing RDAP object.
//
// https://tools.ietf.org/html/rfc7483#section-4.3
type Remark struct {
	DecodeData *DecodeData

	Title       string
	Type        string
	Description []string
	Links       []Link
}

// Language Identifier
// Appears in anywhere, embedded (no separate type):
// Lang string
//
// https://tools.ietf.org/html/rfc7483#section-4.4

// Event represents some event which has occured/may occur in the future..
//
// https://tools.ietf.org/html/rfc7483#section-4.5
type Event struct {
	DecodeData *DecodeData

	Action string `rdap:"eventAction"`
	Actor  string `rdap:"eventActor"`
	Date   string `rdap:"eventDate"`
	Links  []Link
}

// Status indicates the state of a registered object.
// Embedded (no separate type):
// Status []string
//
// https://tools.ietf.org/html/rfc7483#section-4.6

// Port43 indicates the IP/FQDN of a WHOIS server.
// Embedded (no separate type):
// Port43 string
//
// https://tools.ietf.org/html/rfc7483#section-4.7

// PublicID maps a public identifier to an object class.
//
// https://tools.ietf.org/html/rfc7483#section-4.8
type PublicID struct {
	DecodeData *DecodeData

	Type       string
	Identifier string
}

// ObjectClassName specifies the object type as a string.
// Embedded (no separate type):
// ObjectClassName string
//
// https://tools.ietf.org/html/rfc7483#section-4.9

// Common contains fields which may appear anywhere in an RDAP response.
type Common struct {
	Lang string
}
