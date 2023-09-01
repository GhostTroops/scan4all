package asnmap

import (
	"regexp"

	"github.com/asaskevich/govalidator"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type InputType uint8

const (
	ASN InputType = iota
	ASNID
	IP
	Org
	Domain
	Unknown
)

var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9-]+(\.[a-z0-9-]+)+\.?$`)

// checkIfASN checks if the given input is ASN or not,
// its possible to have an org name starting with AS/as prefix.
func checkIfASN(input string) bool {
	if len(input) == 0 {
		return false
	}
	hasASNPrefix := stringsutil.HasPrefixI(input, "AS")
	if hasASNPrefix {
		input = input[2:]
	}
	return hasASNPrefix && checkIfASNId(input)
}

func checkIfASNId(input string) bool {
	if len(input) == 0 {
		return false
	}
	hasNumericId := input != "" && govalidator.IsNumeric(input)
	return hasNumericId
}

func IdentifyInput(input string) InputType {
	switch {
	case iputil.IsIP(input):
		return IP
	case checkIfASN(input):
		return ASN
	case checkIfASNId(input):
		return ASNID
	case domainRegex.MatchString(input):
		return Domain
	default:
		return Org
	}
}
