package ipisp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnexpectedTokens = errors.New("an unexpect token was received while reading response")
)

var (
	bulkEOL = []byte("\r\n")
)

const (
	netcatIPTokensLength  = 7
	netcatASNTokensLength = 5
	cymruNetcatAddress    = "whois.cymru.com:43"
)

// BulkClient uses the WHOIS service to conduct bulk lookups.
type BulkClient struct {
	Conn net.Conn
}

// DialBulkClient returns a connected WHOIS client.
// This client should be used for bulk lookups.
func DialBulkClient(ctx context.Context) (*BulkClient, error) {
	var err error

	client := &BulkClient{}
	var d net.Dialer
	client.Conn, err = d.DialContext(ctx, "tcp", cymruNetcatAddress)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	client.Conn.Write([]byte("begin"))
	client.Conn.Write(bulkEOL)
	client.Conn.Write([]byte("verbose"))
	client.Conn.Write(bulkEOL)

	sc := bufio.NewScanner(client.Conn)

	// Discard first hello line.
	sc.Scan()
	if sc.Err() != nil {
		client.Conn.Close()
		return nil, fmt.Errorf("scan: %w", err)
	}

	return client, nil
}

func (c *BulkClient) LookupIPs(ips ...net.IP) ([]Response, error) {
	var (
		w  = bufio.NewWriter(c.Conn)
		sc = bufio.NewScanner(c.Conn)
	)
	var (
		resp = make([]Response, 0, len(ips))
		err  error
	)

	for _, ip := range ips {
		w.WriteString(ip.String())
		w.Write(bulkEOL)
		if err = w.Flush(); err != nil {
			return resp, err
		}
	}

	// Raw response
	var raw []byte
	var tokens [][]byte

	var finished bool

	// Read results
	for !finished && sc.Scan() {
		raw = sc.Bytes()
		if bytes.HasPrefix(raw, []byte("Error: ")) {
			return resp, errors.New(string(bytes.TrimSpace(bytes.TrimLeft(raw, "Error: "))))
		}
		tokens = bytes.Split(raw, []byte{'|'})

		if len(tokens) != netcatIPTokensLength {
			return resp, ErrUnexpectedTokens
		}

		// Trim excess whitespace from tokens
		for i := range tokens {
			tokens[i] = bytes.TrimSpace(tokens[i])
		}

		re := Response{}

		// Read ASN
		asns := strings.Split(
			strings.TrimSpace(string(tokens[0])),
			" ",
		)
		asn, err := strconv.Atoi(asns[0])
		if err != nil {
			return resp, fmt.Errorf("parse %v: %w", asns[0], err)
		}

		re.ASN = ASN(asn)

		// Read IP
		re.IP = net.ParseIP(string(tokens[1]))

		// Read range
		bgpPrefix := string(tokens[2])
		// Account for 'NA' BGP Prefix responses from the API
		// More info: https://github.com/ammario/ipisp/issues/13
		if bgpPrefix == "NA" {
			bgpPrefix = re.IP.String() + "/32"
		}

		_, re.Range, err = net.ParseCIDR(bgpPrefix)
		if err != nil {
			return resp, fmt.Errorf("parse cidr %q: %w", bgpPrefix, err)
		}

		// Read country
		re.Country = string(bytes.TrimSpace(tokens[3]))
		// Read registry
		re.Registry = string(bytes.ToUpper(tokens[4]))
		// Read allocated. Ignore error as a lot of entries don't have an allocated value.
		re.AllocatedAt, _ = time.Parse("2006-01-02", string(tokens[5]))
		// Read name
		re.ISPName = string(tokens[6])

		// Add to response slice
		resp = append(resp, re)
		if len(resp) == cap(resp) {
			finished = true
		}
	}
	return resp, err
}

// LookupASNs looks up ASNs. Response IP and Range fields are zeroed
func (c *BulkClient) LookupASNs(asns ...ASN) ([]Response, error) {
	var (
		w  = bufio.NewWriter(c.Conn)
		sc = bufio.NewScanner(c.Conn)
	)
	var (
		resp = make([]Response, 0, len(asns))
		err  error
	)

	for _, asn := range asns {
		w.WriteString(asn.String())
		w.Write(bulkEOL)
		if err = w.Flush(); err != nil {
			return resp, err
		}
	}

	c.Conn.SetDeadline(time.Now().Add(time.Second*5 + (time.Second * time.Duration(len(asns)))))

	// Raw response
	var raw []byte
	var tokens [][]byte
	var asn int

	var finished bool

	// Read results
	for !finished && sc.Scan() {
		raw = sc.Bytes()
		if bytes.HasPrefix(raw, []byte("Error: ")) {
			return resp, fmt.Errorf("service error: %s", raw)
		}
		tokens = bytes.Split(raw, []byte{'|'})

		if len(tokens) != netcatASNTokensLength {
			return resp, ErrUnexpectedTokens
		}

		// Trim excess whitespace from tokens
		for i := range tokens {
			tokens[i] = bytes.TrimSpace(tokens[i])
		}

		re := Response{}

		// Read ASN
		if asn, err = strconv.Atoi(string(tokens[0])); err != nil {
			return nil, fmt.Errorf("parse asn %q: %w", tokens[0], err)
		}
		re.ASN = ASN(asn)
		// Read country
		re.Country = string(tokens[1])
		// Read registry
		re.Registry = string(bytes.ToUpper(tokens[2]))
		// Read allocated. Ignore error as a lot of entries don't have an allocated value.
		re.AllocatedAt, _ = time.Parse("2006-01-02", string(tokens[3]))
		// Read name
		re.ISPName = string(tokens[4])

		// Add to response slice
		resp = append(resp, re)
		if len(resp) == cap(resp) {
			finished = true
		}
	}
	return resp, err
}

func (c *BulkClient) Close() error {
	return c.Conn.Close()
}
