// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// Domain represents information about a DNS name and point of delegation.
//
// Domain is a topmost RDAP response object.
type Domain struct {
	DecodeData *DecodeData

	Common
	Conformance     []string `rdap:"rdapConformance"`
	ObjectClassName string

	Notices []Notice

	Handle      string
	LDHName     string `rdap:"ldhName"`
	UnicodeName string

	Variants []Variant

	Nameservers []Nameserver

	SecureDNS *SecureDNS

	Entities []Entity
	Status   []string

	PublicIDs []PublicID `rdap:"publicIds"`
	Remarks   []Remark
	Links     []Link
	Port43    string
	Events    []Event
	Network   *IPNetwork
}

// Variant is a subfield of Domain.
type Variant struct {
	DecodeData *DecodeData

	Common
	Relation     []string
	IDNTable     string `rdap:"idnTable"`
	VariantNames []VariantName
}

// VariantName is a subfield of Variant.
type VariantName struct {
	DecodeData *DecodeData

	Common
	LDHName     string `rdap:"ldhName"`
	UnicodeName string
}

// SecureDNS is ia subfield of Domain.
type SecureDNS struct {
	DecodeData *DecodeData

	Common
	ZoneSigned       *bool
	DelegationSigned *bool
	MaxSigLife       *uint64
	DS               []DSData  `rdap:"dsData"`
	Keys             []KeyData `rdap:"keyData"`
}

// DSData is a subfield of Domain.
type DSData struct {
	DecodeData *DecodeData

	Common
	KeyTag     *uint64
	Algorithm  *uint8
	Digest     string
	DigestType *uint8

	Events []Event
	Links  []Link
}

type KeyData struct {
	DecodeData *DecodeData

	Flags     *uint16
	Protocol  *uint8
	Algorithm *uint8
	PublicKey string

	Events []Event
	Links  []Link
}
