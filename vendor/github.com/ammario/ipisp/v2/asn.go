package ipisp

import (
	"fmt"
	"strconv"
	"strings"
)

// ASN represents an Autonomous Systems Number.
// See https://en.wikipedia.org/wiki/Autonomous_system_(Internet).
type ASN int

// ParseASN parses a string like `AS2341` into ASN `2341`.
func ParseASN(asn string) (ASN, error) {
	// A special value from the API.
	// More info: https://github.com/ammario/ipisp/issues/10.
	if asn == "NA" {
		return -1, nil
	}
	// Make case insensitive
	asn = strings.ToUpper(asn)
	if len(asn) > 2 && asn[:2] == "AS" {
		asn = asn[2:]
	}

	nn, err := strconv.Atoi(asn)
	if err != nil {
		return -1, fmt.Errorf("parse %q: %w", asn, err)
	}
	return ASN(nn), nil
}

// String represents an ASN like `5544`` as `AS5544`.`
func (a ASN) String() string {
	if a == 0 {
		return "N/A"
	}
	return "AS" + strconv.Itoa(int(a))
}
