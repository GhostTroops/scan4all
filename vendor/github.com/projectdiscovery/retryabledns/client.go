package retryabledns

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/retryabledns/doh"
	"github.com/projectdiscovery/retryabledns/hostsfile"
	"github.com/projectdiscovery/retryablehttp-go"
)

var internalRangeCheckerInstance *internalRangeChecker

func init() {
	rand.Seed(time.Now().UnixNano())

	var err error
	internalRangeCheckerInstance, err = newInternalRangeChecker()
	if err != nil {
		fmt.Printf("could not initialize range checker: %s\n", err)
	}
}

// Client is a DNS resolver client to resolve hostnames.
type Client struct {
	resolvers    []Resolver
	options      Options
	serversIndex uint32
	TCPFallback  bool
	udpClient    *dns.Client
	tcpClient    *dns.Client
	dohClient    *doh.Client
	dotClient    *dns.Client
	knownHosts   map[string][]string
}

// New creates a new dns client
func New(baseResolvers []string, maxRetries int) *Client {
	return NewWithOptions(Options{BaseResolvers: baseResolvers, MaxRetries: maxRetries})
}

// New creates a new dns client with options
func NewWithOptions(options Options) *Client {
	parsedBaseResolvers := parseResolvers(deduplicate(options.BaseResolvers))
	var knownHosts map[string][]string
	if options.Hostsfile {
		knownHosts, _ = hostsfile.ParseDefault()
	}
	httpOptions := retryablehttp.DefaultOptionsSingle
	httpOptions.Timeout = options.Timeout
	client := Client{
		options:   options,
		resolvers: parsedBaseResolvers,
		udpClient: &dns.Client{Net: "", Timeout: options.Timeout},
		tcpClient: &dns.Client{Net: TCP.String(), Timeout: options.Timeout},
		dohClient: doh.NewWithOptions(
			doh.Options{
				HttpClient: retryablehttp.NewClient(httpOptions),
			},
		),
		dotClient:  &dns.Client{Net: "tcp-tls", Timeout: options.Timeout},
		knownHosts: knownHosts,
	}
	return &client
}

// ResolveWithSyscall attempts to resolve the host through system calls
func (c *Client) ResolveWithSyscall(host string) (*DNSData, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var d DNSData
	d.Host = host
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			d.A = append(d.A, ip.String())
		} else if ipv6 := ip.To16(); ipv6 != nil {
			d.AAAA = append(d.AAAA, ip.String())
		}
	}

	return &d, nil
}

// Resolve is the underlying resolve function that actually resolves a host
// and gets the ip records for that host.
func (c *Client) Resolve(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeA, dns.TypeAAAA})
}

// Do sends a provided dns request and return the raw native response
func (c *Client) Do(msg *dns.Msg) (*dns.Msg, error) {
	var resp *dns.Msg
	var err error
	for i := 0; i < c.options.MaxRetries; i++ {
		index := atomic.AddUint32(&c.serversIndex, 1)
		resolver := c.resolvers[index%uint32(len(c.resolvers))]

		switch r := resolver.(type) {
		case *NetworkResolver:
			switch r.Protocol {
			case TCP:
				resp, _, err = c.tcpClient.Exchange(msg, resolver.String())
			case UDP:
				resp, _, err = c.udpClient.Exchange(msg, resolver.String())
			case DOT:
				resp, _, err = c.dotClient.Exchange(msg, resolver.String())
			}
		case *DohResolver:
			method := doh.MethodPost
			if r.Protocol == GET {
				method = doh.MethodGet
			}
			resp, err = c.dohClient.QueryWithDOHMsg(method, doh.Resolver{URL: r.URL}, msg)
		}

		if err != nil || resp == nil {
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		// In case we get a non empty answer stop retrying
		return resp, nil
	}
	return resp, errors.New("could not resolve, max retries exceeded")
}

// Query sends a provided dns request and return enriched response
func (c *Client) Query(host string, requestType uint16) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{requestType})
}

// A helper function
func (c *Client) A(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeA})
}

// AAAA helper function
func (c *Client) AAAA(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeAAAA})
}

// MX helper function
func (c *Client) MX(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeMX})
}

// CNAME helper function
func (c *Client) CNAME(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeCNAME})
}

// SOA helper function
func (c *Client) SOA(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeSOA})
}

// TXT helper function
func (c *Client) TXT(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeTXT})
}

// PTR helper function
func (c *Client) PTR(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypePTR})
}

// NS helper function
func (c *Client) NS(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeNS})
}

// QueryMultiple sends a provided dns request and return the data
func (c *Client) QueryMultiple(host string, requestTypes []uint16) (*DNSData, error) {
	var (
		dnsdata DNSData
		err     error
	)

	// integrate data with known hosts in case
	if c.options.Hostsfile {
		if ips, ok := c.knownHosts[host]; ok {
			for _, ip := range ips {
				if iputil.IsIPv4(ip) {
					dnsdata.A = append(dnsdata.A, ip)
				} else if iputil.IsIPv6(ip) {
					dnsdata.AAAA = append(dnsdata.AAAA, ip)
				}
			}
		}
	}

	msg := &dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)

	for _, requestType := range requestTypes {
		name := dns.Fqdn(host)

		// In case of PTR adjust the domain name
		if requestType == dns.TypePTR {
			var err error
			if net.ParseIP(host) != nil {
				name, err = dns.ReverseAddr(host)
				if err != nil {
					return nil, err
				}
			}
		}

		question := dns.Question{
			Name:   name,
			Qtype:  requestType,
			Qclass: dns.ClassINET,
		}
		msg.Question[0] = question

		// Enable Extension Mechanisms for DNS for all messages
		msg.SetEdns0(4096, false)

		var resp *dns.Msg
		for i := 0; i < c.options.MaxRetries; i++ {
			index := atomic.AddUint32(&c.serversIndex, 1)
			resolver := c.resolvers[index%uint32(len(c.resolvers))]

			switch r := resolver.(type) {
			case *NetworkResolver:
				switch r.Protocol {
				case TCP:
					resp, _, err = c.tcpClient.Exchange(msg, resolver.String())
				case UDP:
					resp, _, err = c.udpClient.Exchange(msg, resolver.String())
				case DOT:
					resp, _, err = c.dotClient.Exchange(msg, resolver.String())
				}
			case *DohResolver:
				method := doh.MethodPost
				if r.Protocol == GET {
					method = doh.MethodGet
				}
				resp, err = c.dohClient.QueryWithDOHMsg(method, doh.Resolver{URL: r.URL}, msg)
			}
			if err != nil || resp == nil {
				continue
			}

			// https://github.com/projectdiscovery/retryabledns/issues/25
			if resp.Truncated && c.TCPFallback {
				resp, _, err = c.tcpClient.Exchange(msg, resolver.String())
				if err != nil || resp == nil {
					continue
				}
			}

			err = dnsdata.ParseFromMsg(resp)

			// populate anyway basic info
			dnsdata.Host = host
			dnsdata.StatusCode = dns.RcodeToString[resp.Rcode]
			dnsdata.StatusCodeRaw = resp.Rcode
			dnsdata.Timestamp = time.Now()
			dnsdata.Raw += resp.String()
			dnsdata.Resolver = append(dnsdata.Resolver, resolver.String())

			if err != nil || !dnsdata.contains() {
				continue
			}
			dnsdata.dedupe()

			// stop on success
			if resp.Rcode == dns.RcodeSuccess {
				break
			}
		}
	}

	return &dnsdata, err
}

// QueryParallel sends a provided dns request to multiple resolvers in parallel
func (c *Client) QueryParallel(host string, requestType uint16, resolvers []string) ([]*DNSData, error) {
	msg := dns.Msg{}
	msg.SetQuestion(dns.CanonicalName(host), requestType)

	var dnsdatas []*DNSData

	var wg sync.WaitGroup
	for _, resolver := range resolvers {
		var dnsdata DNSData
		dnsdatas = append(dnsdatas, &dnsdata)
		wg.Add(1)
		go func(resolver string, dnsdata *DNSData) {
			defer wg.Done()
			resp, err := dns.Exchange(msg.Copy(), resolver)
			if err != nil {
				return
			}
			err = dnsdata.ParseFromMsg(resp)
			if err != nil {
				return
			}
			dnsdata.Host = host
			dnsdata.StatusCode = dns.RcodeToString[resp.Rcode]
			dnsdata.StatusCodeRaw = resp.Rcode
			dnsdata.Timestamp = time.Now()
			dnsdata.Resolver = append(dnsdata.Resolver, resolver)
			dnsdata.RawResp = resp
			dnsdata.Raw = resp.String()
			dnsdata.dedupe()
		}(resolver, &dnsdata)
	}

	wg.Wait()

	return dnsdatas, nil
}

// QueryMultiple sends a provided dns request and return the data
func (c *Client) Trace(host string, requestType uint16, maxrecursion int) (*TraceData, error) {
	var tracedata TraceData
	host = dns.CanonicalName(host)
	msg := dns.Msg{}
	msg.SetQuestion(host, requestType)
	servers := RootDNSServersIPv4
	seenNS := make(map[string]struct{})
	for i := 1; i < maxrecursion; i++ {
		msg.SetQuestion(host, requestType)
		dnsdatas, err := c.QueryParallel(host, requestType, servers)
		if err != nil {
			return nil, err
		}

		for _, server := range servers {
			seenNS[server] = struct{}{}
		}

		if len(dnsdatas) == 0 {
			return &tracedata, nil
		}

		for _, dnsdata := range dnsdatas {
			if dnsdata != nil && len(dnsdata.Resolver) > 0 {
				tracedata.DNSData = append(tracedata.DNSData, dnsdata)
			}
		}

		var newNSResolvers []string
		var nextCname string
		for _, d := range dnsdatas {
			// Add ns records as new resolvers
			for _, ns := range d.NS {
				ips, err := net.LookupIP(ns)
				if err != nil {
					continue
				}
				for _, ip := range ips {
					if ip.To4() != nil {
						newNSResolvers = append(newNSResolvers, net.JoinHostPort(ip.String(), "53"))
					}
				}
			}
			// Follow CNAME - should happen at the final step of the trace
			for _, cname := range d.CNAME {
				if nextCname == "" {
					nextCname = cname
					break
				}
			}
		}
		newNSResolvers = deduplicate(newNSResolvers)

		// if we have no new resolvers => return
		if len(newNSResolvers) == 0 {
			break
		}

		// Pick a random server
		randomServer := newNSResolvers[rand.Intn(len(newNSResolvers))]
		// If we pick the same resolver and we are not following any new cname => return
		if _, ok := seenNS[randomServer]; ok && nextCname == "" {
			break
		}

		servers = []string{randomServer}

		// follow cname if any
		if nextCname != "" {
			host = nextCname
		}
	}

	return &tracedata, nil
}

// DNSData is the data for a DNS request response
type DNSData struct {
	Host           string     `json:"host,omitempty"`
	TTL            int        `json:"ttl,omitempty"`
	Resolver       []string   `json:"resolver,omitempty"`
	A              []string   `json:"a,omitempty"`
	AAAA           []string   `json:"aaaa,omitempty"`
	CNAME          []string   `json:"cname,omitempty"`
	MX             []string   `json:"mx,omitempty"`
	PTR            []string   `json:"ptr,omitempty"`
	SOA            []string   `json:"soa,omitempty"`
	NS             []string   `json:"ns,omitempty"`
	TXT            []string   `json:"txt,omitempty"`
	Raw            string     `json:"raw,omitempty"`
	HasInternalIPs bool       `json:"has_internal_ips"`
	InternalIPs    []string   `json:"internal_ips,omitempty"`
	StatusCode     string     `json:"status_code,omitempty"`
	StatusCodeRaw  int        `json:"status_code_raw,omitempty"`
	TraceData      *TraceData `json:"trace,omitempty"`
	RawResp        *dns.Msg   `json:"raw_resp,omitempty"`
	Timestamp      time.Time  `json:"timestamp,omitempty"`
}

// CheckInternalIPs when set to true returns if DNS response IPs
// belong to internal IP ranges.
var CheckInternalIPs = false

// ParseFromMsg and enrich data
func (d *DNSData) ParseFromMsg(msg *dns.Msg) error {
	allRecords := append(msg.Answer, msg.Extra...)
	allRecords = append(allRecords, msg.Ns...)

	for _, record := range allRecords {
		switch recordType := record.(type) {
		case *dns.A:
			if CheckInternalIPs && internalRangeCheckerInstance != nil && internalRangeCheckerInstance.ContainsIPv4(recordType.A) {
				d.HasInternalIPs = true
				d.InternalIPs = append(d.InternalIPs, trimChars(recordType.A.String()))
			}
			d.A = append(d.A, trimChars(recordType.A.String()))
		case *dns.NS:
			d.NS = append(d.NS, trimChars(recordType.Ns))
		case *dns.CNAME:
			d.CNAME = append(d.CNAME, trimChars(recordType.Target))
		case *dns.SOA:
			d.SOA = append(d.SOA, trimChars(recordType.Ns))
			d.SOA = append(d.SOA, trimChars(recordType.Mbox))
		case *dns.PTR:
			d.PTR = append(d.PTR, trimChars(recordType.Ptr))
		case *dns.MX:
			d.MX = append(d.MX, trimChars(recordType.Mx))
		case *dns.TXT:
			for _, txt := range recordType.Txt {
				d.TXT = append(d.TXT, trimChars(txt))
			}
		case *dns.AAAA:
			if CheckInternalIPs && internalRangeCheckerInstance.ContainsIPv6(recordType.AAAA) {
				d.HasInternalIPs = true
				d.InternalIPs = append(d.InternalIPs, trimChars(recordType.AAAA.String()))
			}
			d.AAAA = append(d.AAAA, trimChars(recordType.AAAA.String()))
		}
	}

	return nil
}

func (d *DNSData) contains() bool {
	return len(d.A) > 0 || len(d.AAAA) > 0 || len(d.CNAME) > 0 || len(d.MX) > 0 || len(d.NS) > 0 || len(d.PTR) > 0 || len(d.TXT) > 0 || len(d.SOA) > 0
}

// JSON returns the object as json string
func (d *DNSData) JSON() (string, error) {
	b, err := json.Marshal(&d)
	return string(b), err
}

func trimChars(s string) string {
	return strings.TrimRight(s, ".")
}

func (d *DNSData) dedupe() {
	d.Resolver = deduplicate(d.Resolver)
	d.A = deduplicate(d.A)
	d.AAAA = deduplicate(d.AAAA)
	d.CNAME = deduplicate(d.CNAME)
	d.MX = deduplicate(d.MX)
	d.PTR = deduplicate(d.PTR)
	d.SOA = deduplicate(d.SOA)
	d.NS = deduplicate(d.NS)
	d.TXT = deduplicate(d.TXT)
}

// Marshal encodes the dnsdata to a binary representation
func (d *DNSData) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(d)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Unmarshal decodes the dnsdata from a binary representation
func (d *DNSData) Unmarshal(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(&d)
}

// deduplicate returns a new slice with duplicates values removed.
func deduplicate(s []string) []string {
	if len(s) < 2 {
		return s
	}
	var results []string
	seen := make(map[string]struct{})
	for _, val := range s {
		if _, ok := seen[val]; !ok {
			results = append(results, val)
			seen[val] = struct{}{}
		}
	}
	return results
}

// TraceData contains the trace information for a dns query
type TraceData struct {
	Host    string     `json:"host,omitempty"`
	DNSData []*DNSData `json:"chain,omitempty"`
}
