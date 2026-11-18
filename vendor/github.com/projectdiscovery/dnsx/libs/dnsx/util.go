package dnsx

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// StringToRequestType conversion helper
func StringToRequestType(tp string) (rt uint16, err error) {
	tp = strings.TrimSpace(strings.ToUpper(tp))
	switch tp {
	case "A":
		rt = dns.TypeA
	case "NS":
		rt = dns.TypeNS
	case "CNAME":
		rt = dns.TypeCNAME
	case "SOA":
		rt = dns.TypeSOA
	case "PTR":
		rt = dns.TypePTR
	case "ANY":
		rt = dns.TypeANY
	case "MX":
		rt = dns.TypeMX
	case "TXT":
		rt = dns.TypeTXT
	case "SRV":
		rt = dns.TypeSRV
	case "AAAA":
		rt = dns.TypeAAAA
	default:
		rt = dns.TypeNone
		err = fmt.Errorf("incorrect type")
	}

	return
}
