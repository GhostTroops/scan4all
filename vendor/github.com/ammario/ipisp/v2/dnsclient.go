package ipisp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const hexDigit = "0123456789abcdef"

// LookupIP looks up a single IP with the API.
// The service recommends that bulk lookups use the BulkClient out of respect
// for their server load.
func LookupIP(ctx context.Context, ip net.IP) (*Response, error) {
	var r net.Resolver
	lookupName, err := formatDNSLookupName(ip)
	if err != nil {
		return nil, err
	}
	txts, err := r.LookupTXT(ctx, lookupName)
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		values := strings.Split(txt, "|")
		if len(values) != 5 {
			return nil, fmt.Errorf("unrecognized response: %s", txt)
		}
		for k := range values {
			values[k] = strings.TrimSpace(values[k])
		}

		ret := &Response{
			IP:       ip,
			Registry: strings.ToUpper(values[3]),
		}

		var err error
		asn, err := ParseASN(values[0])
		if err != nil {
			return nil, fmt.Errorf("parse ASN %q: %w", values[0], err)
		}
		ret.ASN = asn
		ret.Country = strings.TrimSpace(values[2])
		_, ret.Range, err = net.ParseCIDR(values[1])
		if err != nil {
			return nil, fmt.Errorf("parse range (%s): %s", values[1], err)
		}

		if values[4] != "" { // There's not always an allocation date available :(
			ret.AllocatedAt, err = time.Parse("2006-01-02", values[4])
			if err != nil {
				return nil, fmt.Errorf("parse date (%s): %s", values[4], err)
			}
		}

		asnResponse, err := LookupASN(ctx, ret.ASN)
		if err != nil {
			return nil, fmt.Errorf("retrieve ASN (%s): %s", ret.ASN.String(), err.Error())
		}

		ret.ISPName = asnResponse.ISPName
		return ret, nil

	}

	return nil, fmt.Errorf("no records found")
}

func LookupASN(ctx context.Context, asn ASN) (*Response, error) {
	var r net.Resolver
	txts, err := r.LookupTXT(ctx, asn.String()+".asn.cymru.com")
	if err != nil {
		return nil, err
	}

	for _, txt := range txts {
		values := strings.Split(txt, "|")
		if len(values) != 5 {
			return nil, fmt.Errorf("Received unrecognized response in AS lookup: %s", txt)
		}
		for k := range values {
			values[k] = strings.TrimSpace(values[k])
		}

		resp := &Response{
			ASN:      asn,
			Registry: strings.ToUpper(values[2]),
			ISPName:  values[4],
		}

		resp.Country = values[1]

		if values[3] != "" {
			resp.AllocatedAt, err = time.Parse("2006-01-02", values[3])
			if err != nil {
				return nil, fmt.Errorf("Could not parse date (%s): %s", values[3], err)
			}
		}

		return resp, nil
	}

	return nil, fmt.Errorf("no records found")
}

func formatDNSLookupName(ip net.IP) (string, error) {
	switch {
	case len(ip) == net.IPv4len || ip.To4() != nil:
		ip = ip.To4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ip[3], ip[2], ip[1], ip[0]), nil
	case len(ip) == net.IPv6len:
		sep := []byte(`.`)[0]
		b := make([]byte, 0, 64)
		for i := 16; i >= 2; i -= 2 {
			for j := 0; j <= 3; j++ {
				v := ((uint32(ip[i-2]) << 8) | uint32(ip[i-1])) >> uint(j*4)
				b = append(b, hexDigit[v&0xf], sep)
			}
		}
		return fmt.Sprintf("%s.origin6.asn.cymru.com", b[:63]), nil
	default:
		return "", errors.New("invalid IP length")
	}
}
