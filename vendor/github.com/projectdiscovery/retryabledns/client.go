package retryabledns

import (
	"bytes"
	"context"
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
	"github.com/projectdiscovery/retryabledns/doh"
	"github.com/projectdiscovery/retryabledns/hostsfile"
	iputil "github.com/projectdiscovery/utils/ip"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var internalRangeCheckerInstance *internalRangeChecker

func init() {
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
	udpConnPool  mapsutil.SyncLockMap[string, *ConnPool]
	tcpClient    *dns.Client
	dohClient    *doh.Client
	dotClient    *dns.Client
	knownHosts   map[string][]string
}

// New creates a new dns client
func New(baseResolvers []string, maxRetries int) (*Client, error) {
	return NewWithOptions(Options{BaseResolvers: baseResolvers, MaxRetries: maxRetries})
}

// New creates a new dns client with options
func NewWithOptions(options Options) (*Client, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	parsedBaseResolvers := parseResolvers(sliceutil.Dedupe(options.BaseResolvers))
	var knownHosts map[string][]string
	if options.Hostsfile {
		knownHosts, _ = hostsfile.ParseDefault()
	}

	httpClient := doh.NewHttpClientWithTimeout(options.Timeout)

	client := Client{
		options:   options,
		resolvers: parsedBaseResolvers,
		udpClient: &dns.Client{
			Net:     "",
			Timeout: options.Timeout,
			Dialer: &net.Dialer{
				LocalAddr: options.GetLocalAddr(UDP),
			},
		},
		tcpClient: &dns.Client{
			Net:     TCP.String(),
			Timeout: options.Timeout,
			Dialer: &net.Dialer{
				LocalAddr: options.GetLocalAddr(TCP),
			},
		},
		dohClient: doh.NewWithOptions(
			doh.Options{
				HttpClient: httpClient,
			},
		),
		dotClient: &dns.Client{
			Net:     "tcp-tls",
			Timeout: options.Timeout,
			Dialer: &net.Dialer{
				LocalAddr: options.GetLocalAddr(TCP),
			},
		},
		knownHosts: knownHosts,
	}
	if options.ConnectionPoolThreads > 1 {
		client.udpConnPool = mapsutil.SyncLockMap[string, *ConnPool]{
			Map: make(mapsutil.Map[string, *ConnPool]),
		}
		for _, resolver := range client.resolvers {
			resolverHost, resolverPort, err := net.SplitHostPort(resolver.String())
			if err != nil {
				return nil, err
			}
			networkResolver := NetworkResolver{
				Protocol: UDP,
				Port:     resolverPort,
				Host:     resolverHost,
			}
			udpConnPool, err := NewConnPool(networkResolver, options.ConnectionPoolThreads)
			if err != nil {
				return nil, err
			}
			_ = client.udpConnPool.Set(resolver.String(), udpConnPool)
		}
	}
	return &client, nil
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
				if c.options.ConnectionPoolThreads > 1 {
					if udpConnPool, ok := c.udpConnPool.Get(resolver.String()); ok {
						resp, _, err = udpConnPool.Exchange(context.TODO(), c.udpClient, msg)
					}
				} else {
					resp, _, err = c.udpClient.Exchange(msg, resolver.String())
				}
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

// SRV helper function
func (c *Client) SRV(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeSRV})
}

// PTR helper function
func (c *Client) PTR(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypePTR})
}

// ANY helper function
func (c *Client) ANY(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeANY})
}

// NS helper function
func (c *Client) NS(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeNS})
}

func (c *Client) AXFR(host string) (*AXFRData, error) {
	return c.axfr(host)
}

// QueryMultiple sends a provided dns request and return the data with a specific resolver
func (c *Client) QueryMultipleWithResolver(host string, requestTypes []uint16, resolver Resolver) (*DNSData, error) {
	return c.queryMultiple(host, requestTypes, resolver)
}

// CAA helper function
func (c *Client) CAA(host string) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{dns.TypeCAA})
}

// QueryMultiple sends a provided dns request and return the data
func (c *Client) QueryMultiple(host string, requestTypes []uint16) (*DNSData, error) {
	return c.queryMultiple(host, requestTypes, nil)
}

// QueryMultiple sends a provided dns request and return the data
func (c *Client) queryMultiple(host string, requestTypes []uint16, resolver Resolver) (*DNSData, error) {
	var (
		hasResolver bool = resolver != nil
		dnsdata     DNSData
		err         error
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
		if len(dnsdata.AAAA)+len(dnsdata.A) > 0 {
			dnsdata.HostsFile = true
		}
	}

	msg := &dns.Msg{}
	msg.Id = dns.Id()
	msg.SetEdns0(4096, false)

	for _, requestType := range requestTypes {
		name := dns.Fqdn(host)
		msg.Question = make([]dns.Question, 1)

		switch requestType {
		case dns.TypeAXFR:
			msg.SetAxfr(name)
		case dns.TypePTR: // In case of PTR adjust the domain name
			var err error
			if net.ParseIP(host) != nil {
				name, err = dns.ReverseAddr(host)
				if err != nil {
					return nil, err
				}
			}
			fallthrough
		default:
			// Enable Extension Mechanisms for DNS for all messages
			msg.RecursionDesired = true
			question := dns.Question{
				Name:   name,
				Qtype:  requestType,
				Qclass: dns.ClassINET,
			}
			msg.Question[0] = question
		}

		var (
			resp   *dns.Msg
			trResp chan *dns.Envelope
		)
		for i := 0; i < c.options.MaxRetries; i++ {
			index := atomic.AddUint32(&c.serversIndex, 1)
			if !hasResolver {
				resolver = c.resolvers[index%uint32(len(c.resolvers))]
			}
			switch r := resolver.(type) {
			case *NetworkResolver:
				if requestType == dns.TypeAXFR {
					var dnsconn *dns.Conn
					switch r.Protocol {
					case TCP:
						dnsconn, err = c.tcpClient.Dial(resolver.String())
					case UDP:
						dnsconn, err = c.udpClient.Dial(resolver.String())
					case DOT:
						dnsconn, err = c.dotClient.Dial(resolver.String())
					default:
						dnsconn, err = c.tcpClient.Dial(resolver.String())
					}
					if err != nil {
						break
					}
					defer dnsconn.Close()
					dnsTransfer := &dns.Transfer{Conn: dnsconn}
					trResp, err = dnsTransfer.In(msg, resolver.String())
				} else {
					switch r.Protocol {
					case TCP:
						resp, _, err = c.tcpClient.Exchange(msg, resolver.String())
					case UDP:
						if c.options.ConnectionPoolThreads > 1 {
							if udpConnPool, ok := c.udpConnPool.Get(resolver.String()); ok {
								resp, _, err = udpConnPool.Exchange(context.TODO(), c.udpClient, msg)
							}
						} else {
							resp, _, err = c.udpClient.Exchange(msg, resolver.String())
						}
					case DOT:
						resp, _, err = c.dotClient.Exchange(msg, resolver.String())
					}
				}
			case *DohResolver:
				method := doh.MethodPost
				if r.Protocol == GET {
					method = doh.MethodGet
				}
				resp, err = c.dohClient.QueryWithDOHMsg(method, doh.Resolver{URL: r.URL}, msg)
			}

			if err != nil || (trResp == nil && resp == nil) {
				continue
			}

			// https://github.com/projectdiscovery/retryabledns/issues/25
			if resp != nil && resp.Truncated && c.TCPFallback {
				resp, _, err = c.tcpClient.Exchange(msg, resolver.String())
				if err != nil || resp == nil {
					continue
				}
			}

			switch requestType {
			case dns.TypeAXFR:
				err = dnsdata.ParseFromEnvelopeChan(trResp)
			default:
				err = dnsdata.ParseFromMsg(resp)
			}

			// populate anyway basic info
			dnsdata.Host = host
			switch {
			case resp != nil:
				dnsdata.StatusCode = dns.RcodeToString[resp.Rcode]
				dnsdata.StatusCodeRaw = resp.Rcode
				dnsdata.Raw += resp.String()
			case trResp != nil:
				// pass
			}
			dnsdata.Timestamp = time.Now()
			dnsdata.Resolver = append(dnsdata.Resolver, resolver.String())

			if err != nil || !dnsdata.contains() {
				continue
			}
			dnsdata.dedupe()

			// stop on success
			if resp != nil && resp.Rcode == dns.RcodeSuccess {
				break
			}
			if trResp != nil {
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

// Trace the requested domain with the provided query type
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
		newNSResolvers = sliceutil.Dedupe(newNSResolvers)

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

func (c *Client) axfr(host string) (*AXFRData, error) {
	// obtain ns servers
	dnsData, err := c.NS(host)
	if err != nil {
		return nil, err
	}
	// resolve ns servers to ips
	var resolvers []Resolver

	for _, ns := range dnsData.NS {
		nsData, err := c.A(ns)
		if err != nil {
			continue
		}
		for _, a := range nsData.A {
			resolvers = append(resolvers, &NetworkResolver{Protocol: TCP, Host: a, Port: "53"})
		}
	}

	resolvers = append(resolvers, c.resolvers...)

	var data []*DNSData
	// perform zone transfer for each ns
	for _, resolver := range resolvers {
		nsData, err := c.QueryMultipleWithResolver(host, []uint16{dns.TypeAXFR}, resolver)
		if err != nil {
			continue
		}
		data = append(data, nsData)
	}

	return &AXFRData{Host: host, DNSData: data}, nil
}

func (c *Client) Close() {
	_ = c.udpConnPool.Iterate(func(_ string, connPool *ConnPool) error {
		connPool.Close()
		return nil
	})
}

// DNSData is the data for a DNS request response
type DNSData struct {
	Host           string     `json:"host,omitempty"`
	TTL            uint32     `json:"ttl,omitempty"`
	Resolver       []string   `json:"resolver,omitempty"`
	A              []string   `json:"a,omitempty"`
	AAAA           []string   `json:"aaaa,omitempty"`
	CNAME          []string   `json:"cname,omitempty"`
	MX             []string   `json:"mx,omitempty"`
	PTR            []string   `json:"ptr,omitempty"`
	SOA            []SOA      `json:"soa,omitempty"`
	NS             []string   `json:"ns,omitempty"`
	TXT            []string   `json:"txt,omitempty"`
	SRV            []string   `json:"srv,omitempty"`
	CAA            []string   `json:"caa,omitempty"`
	AllRecords     []string   `json:"all,omitempty"`
	Raw            string     `json:"raw,omitempty"`
	HasInternalIPs bool       `json:"has_internal_ips,omitempty"`
	InternalIPs    []string   `json:"internal_ips,omitempty"`
	StatusCode     string     `json:"status_code,omitempty"`
	StatusCodeRaw  int        `json:"status_code_raw,omitempty"`
	TraceData      *TraceData `json:"trace,omitempty"`
	AXFRData       *AXFRData  `json:"axfr,omitempty"`
	RawResp        *dns.Msg   `json:"raw_resp,omitempty"`
	Timestamp      time.Time  `json:"timestamp,omitempty"`
	HostsFile      bool       `json:"hosts_file,omitempty"`
}

type SOA struct {
	Name    string `json:"name,omitempty"`
	NS      string `json:"ns,omitempty"`
	Mbox    string `json:"mailbox,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minttl  uint32 `json:"minttl,omitempty"`
}

// CheckInternalIPs when set to true returns if DNS response IPs
// belong to internal IP ranges.
var CheckInternalIPs = false

func (d *DNSData) ParseFromRR(rrs []dns.RR) error {
	for _, record := range rrs {
		if d.TTL == 0 && record.Header().Ttl > 0 {
			d.TTL = record.Header().Ttl
		}
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
			d.SOA = append(d.SOA, SOA{
				Name:    trimChars(recordType.Hdr.Name),
				NS:      trimChars(recordType.Ns),
				Mbox:    trimChars(recordType.Mbox),
				Serial:  recordType.Serial,
				Refresh: recordType.Refresh,
				Retry:   recordType.Retry,
				Expire:  recordType.Expire,
				Minttl:  recordType.Minttl,
			},
			)
		case *dns.PTR:
			d.PTR = append(d.PTR, trimChars(recordType.Ptr))
		case *dns.MX:
			d.MX = append(d.MX, trimChars(recordType.Mx))
		case *dns.CAA:
			d.CAA = append(d.CAA, trimChars(recordType.Value))
		case *dns.TXT:
			for _, txt := range recordType.Txt {
				d.TXT = append(d.TXT, trimChars(txt))
			}
		case *dns.SRV:
			d.SRV = append(d.SRV, trimChars(recordType.Target))
		case *dns.AAAA:
			if CheckInternalIPs && internalRangeCheckerInstance.ContainsIPv6(recordType.AAAA) {
				d.HasInternalIPs = true
				d.InternalIPs = append(d.InternalIPs, trimChars(recordType.AAAA.String()))
			}
			d.AAAA = append(d.AAAA, trimChars(recordType.AAAA.String()))
		}
		d.AllRecords = append(d.AllRecords, record.String())
	}
	return nil
}

// ParseFromMsg and enrich data
func (d *DNSData) ParseFromMsg(msg *dns.Msg) error {
	allRecords := append(msg.Answer, msg.Extra...)
	allRecords = append(allRecords, msg.Ns...)
	return d.ParseFromRR(allRecords)
}

func (d *DNSData) ParseFromEnvelopeChan(envChan chan *dns.Envelope) error {
	var allRecords []dns.RR
	for env := range envChan {
		if env.Error != nil {
			return env.Error
		}
		allRecords = append(allRecords, env.RR...)
	}
	return d.ParseFromRR(allRecords)
}

func (d *DNSData) contains() bool {
	return len(d.A) > 0 || len(d.AAAA) > 0 || len(d.CNAME) > 0 || len(d.MX) > 0 || len(d.NS) > 0 || len(d.PTR) > 0 || len(d.TXT) > 0 || len(d.SRV) > 0 || len(d.SOA) > 0 || len(d.CAA) > 0
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
	d.Resolver = sliceutil.Dedupe(d.Resolver)
	d.A = sliceutil.Dedupe(d.A)
	d.AAAA = sliceutil.Dedupe(d.AAAA)
	d.CNAME = sliceutil.Dedupe(d.CNAME)
	d.MX = sliceutil.Dedupe(d.MX)
	d.PTR = sliceutil.Dedupe(d.PTR)
	d.NS = sliceutil.Dedupe(d.NS)
	d.TXT = sliceutil.Dedupe(d.TXT)
	d.SRV = sliceutil.Dedupe(d.SRV)
	d.CAA = sliceutil.Dedupe(d.CAA)
	d.AllRecords = sliceutil.Dedupe(d.AllRecords)
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

// TraceData contains the trace information for a dns query
type TraceData struct {
	Host    string     `json:"host,omitempty"`
	DNSData []*DNSData `json:"chain,omitempty"`
}

type AXFRData struct {
	Host    string     `json:"host,omitempty"`
	DNSData []*DNSData `json:"chain,omitempty"`
}

// GetSOARecords returns the NS and Mbox of all SOA records as a string slice
func (d *DNSData) GetSOARecords() []string {
	var soaRecords []string
	for _, soa := range d.SOA {
		soaRecords = append(soaRecords, soa.NS, soa.Mbox)
	}
	return soaRecords
}
