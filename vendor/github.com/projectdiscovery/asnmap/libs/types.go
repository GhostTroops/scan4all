package asnmap

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type Result struct {
	Timestamp  string   `json:"timestamp,omitempty" csv:"timestamp"`
	Input      string   `json:"input" csv:"input"`
	ASN        string   `json:"as_number" csv:"as_number"`
	ASN_org    string   `json:"as_name" csv:"as_name"`
	AS_country string   `json:"as_country" csv:"as_country"`
	AS_range   []string `json:"as_range" csv:"as_range"`
}

// To model http response from server
type Response struct {
	FirstIp string `json:"first_ip,omitempty"`
	LastIp  string `json:"last_ip,omitempty"`
	Input   string `json:"-"` // added by client
	ASN     int    `json:"asn,omitempty"`
	Country string `json:"country,omitempty"`
	Org     string `json:"org,omitempty"`
}

func (r Response) Equal(r2 Response) bool {
	return r.ASN == r2.ASN && strings.EqualFold(r.Org, r2.Org)
}

type InputType uint8

const (
	ASN InputType = iota
	ASNID
	IP
	Org
	Domain
	Unknown
)

var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9-_]+(\.[a-z0-9-]+)+\.?$`)

func MapToResults(output []*Response) ([]*Result, error) {
	results := make([]*Result, 0, len(output))
	for _, res := range output {
		result, err := mapToResult(res)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func mapToResult(resp *Response) (*Result, error) {
	result := &Result{}
	result.Timestamp = time.Now().Local().String()
	result.Input = attachPrefix(resp.Input)
	result.ASN = attachPrefix(strconv.Itoa(resp.ASN))
	result.ASN_org = resp.Org
	result.AS_country = resp.Country
	cidrs, err := GetCIDR([]*Response{resp})
	if err != nil {
		return nil, err
	}
	result.AS_range = convertIPsToStringSlice(cidrs)
	return result, nil
}

// attachPrefix func attaches 'AS' prefix to ASN numbers
func attachPrefix(input string) string {
	inp := input
	if _, err := strconv.Atoi(input); err == nil {
		inp = "AS" + input
	}
	return inp
}

func convertIPsToStringSlice(ips []*net.IPNet) []string {
	var res []string
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	return res
}

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
