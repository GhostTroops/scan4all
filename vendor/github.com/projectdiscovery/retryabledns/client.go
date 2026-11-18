package retryabledns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"slices"
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
	"golang.org/x/net/proxy"
)

var (
	// DefaultMaxPerCNAMEFollows is the default number of times a CNAME can be followed within a trace
	DefaultMaxPerCNAMEFollows = 32

	// ErrRetriesExceeded is the error returned when the max retries are exceeded
	ErrRetriesExceeded = errors.New("could not resolve, max retries exceeded")
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
	// udpClient, tcpClient and dotClient reach resolvers only through
	// exchange and dial, so every connection goes through the proxy when
	// Proxy is set.
	udpClient   *dns.Client
	udpConnPool mapsutil.SyncLockMap[string, *ConnPool]
	tcpClient   *dns.Client
	dohClient   *doh.Client
	dotClient   *dns.Client
	proxyDialer proxy.ContextDialer
	knownHosts  map[string][]string
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

	if options.MaxPerCNAMEFollows == 0 {
		options.MaxPerCNAMEFollows = DefaultMaxPerCNAMEFollows
	}

	httpClient := doh.NewHttpClient(
		doh.WithTimeout(options.Timeout),
		doh.WithInsecureSkipVerify(),
		doh.WithProxy(options.Proxy), // no-op if empty
	)

	udpDialer := &net.Dialer{LocalAddr: options.GetLocalAddr(UDP)}
	tcpDialer := &net.Dialer{LocalAddr: options.GetLocalAddr(TCP)}
	dotDialer := &net.Dialer{LocalAddr: options.GetLocalAddr(TCP)}

	udpClient := &dns.Client{
		Net:     "",
		Timeout: options.Timeout,
		Dialer:  udpDialer,
	}
	tcpClient := &dns.Client{
		Net:     TCP.String(),
		Timeout: options.Timeout,
		Dialer:  tcpDialer,
	}
	dohClient := doh.NewWithOptions(
		doh.Options{
			HttpClient: httpClient,
		},
	)
	dotClient := &dns.Client{
		Net:     "tcp-tls",
		Timeout: options.Timeout,
		Dialer:  dotDialer,
	}

	client := Client{
		options:    options,
		resolvers:  parsedBaseResolvers,
		udpClient:  udpClient,
		tcpClient:  tcpClient,
		dohClient:  dohClient,
		dotClient:  dotClient,
		knownHosts: knownHosts,
	}

	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		// The hop to a SOCKS5 proxy is always TCP, so one dialer serves every
		// resolver protocol.
		proxyDialer, err := proxy.FromURL(proxyURL, tcpDialer)
		if err != nil {
			return nil, fmt.Errorf("error creating proxy dialer: %v", err)
		}
		// DialContext is what lets Timeout bound the proxy handshake.
		contextDialer, ok := proxyDialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("proxy dialer for scheme %q does not support timeouts", proxyURL.Scheme)
		}
		client.proxyDialer = contextDialer
	}

	// Pool exactly the resolvers that exchange sends through udpClient: UDP
	// resolvers, and only without a proxy, since with one clientFor sends them
	// over TCP.
	if options.ConnectionPoolThreads > 1 {
		client.udpConnPool = mapsutil.SyncLockMap[string, *ConnPool]{
			Map: make(mapsutil.Map[string, *ConnPool]),
		}
		for _, resolver := range client.resolvers {
			r, ok := resolver.(*NetworkResolver)
			if !ok || client.clientFor(r.Protocol) != client.udpClient {
				continue
			}
			udpConnPool, err := NewConnPool(*r, options.ConnectionPoolThreads)
			if err != nil {
				return nil, err
			}
			_ = client.udpConnPool.Set(r.String(), udpConnPool)
		}
	}
	return &client, nil
}

// ResolveWithSyscall resolves host to A and AAAA records using the operating
// system's resolver. It ignores the client's options, including Proxy,
// BaseResolvers, and Timeout, so its lookups never go through the proxy. Call
// Resolve to apply them.
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

		resp, err = c.query(msg, resolver)
		if err != nil || resp == nil {
			continue
		}

		if !c.options.exitOnRcode(resp.Rcode) {
			continue
		}

		// In case we get a non empty answer stop retrying
		return resp, nil
	}
	// When ExitOnStatusCodes is set, suppress non-definitive trailing
	// responses so callers can't mistake them for an answer.
	if len(c.options.ExitOnStatusCodes) > 0 && resp != nil && !c.options.exitOnRcode(resp.Rcode) {
		resp = nil
	}
	// Keep the last attempt's error so callers can tell, for example, a
	// proxy failure from a resolver failure. With no error (the last
	// attempt got a non-definitive response) return the bare sentinel.
	if err != nil {
		return resp, errors.Join(ErrRetriesExceeded, err)
	}
	return resp, ErrRetriesExceeded
}

// query sends msg to resolver and returns the reply. It either sends the query
// or returns an error, so a retry loop can't mistake a skipped attempt for an
// empty answer.
func (c *Client) query(msg *dns.Msg, resolver Resolver) (*dns.Msg, error) {
	switch r := resolver.(type) {
	case *NetworkResolver:
		return c.exchange(msg, r.Protocol, r.String())
	case *DohResolver:
		method := doh.MethodPost
		if r.Protocol == GET {
			method = doh.MethodGet
		}
		return c.dohClient.QueryWithDOHMsg(method, doh.Resolver{URL: r.URL}, msg)
	default:
		return nil, fmt.Errorf("unsupported resolver type %T", resolver)
	}
}

// exchange sends msg to the resolver at addr over protocol. Any connection it
// opens is closed before it returns.
func (c *Client) exchange(msg *dns.Msg, protocol Protocol, addr string) (*dns.Msg, error) {
	client := c.clientFor(protocol)
	if client == nil {
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	// Pools exist only for BaseResolvers, so any other resolver gets a
	// connection of its own.
	if client == c.udpClient {
		if pool, ok := c.udpConnPool.Get(addr); ok {
			resp, _, err := pool.Exchange(context.TODO(), client, msg)
			return resp, err
		}
	}
	conn, err := c.dial(client, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	resp, _, err := client.ExchangeWithConn(msg, conn)
	return resp, err
}

// clientFor returns the client that queries a resolver over protocol, or nil
// if the protocol is unsupported. SOCKS5 relays only TCP, so with a proxy UDP
// resolvers are queried over TCP.
func (c *Client) clientFor(protocol Protocol) *dns.Client {
	if c.proxyDialer != nil && protocol == UDP {
		protocol = TCP
	}
	switch protocol {
	case UDP:
		return c.udpClient
	case TCP:
		return c.tcpClient
	case DOT:
		return c.dotClient
	}
	return nil
}

// dial opens a connection for client to the resolver at addr, through the
// proxy when one is set. Timeout bounds the whole setup, including the proxy
// and TLS handshakes, which otherwise wait forever on a peer that accepts the
// connection but never answers.
func (c *Client) dial(client *dns.Client, addr string) (*dns.Conn, error) {
	ctx := context.Background()
	if c.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.options.Timeout)
		defer cancel()
	}
	if c.proxyDialer != nil {
		return c.dialProxy(ctx, client, addr)
	}
	// client.Timeout doesn't bound the dial: dns.Client applies it only to a
	// dialer it builds itself, and client has one of ours.
	return client.DialContext(ctx, addr)
}

// dialProxy does what client.DialContext does, but through the proxy: it opens
// a TCP connection to addr and, for DoT, starts TLS on it.
func (c *Client) dialProxy(ctx context.Context, client *dns.Client, addr string) (*dns.Conn, error) {
	conn, err := c.proxyDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if client.Net == "tcp-tls" {
		// Like tls.Dialer, verify the certificate against the host in addr
		// unless the client's config names a server.
		config := client.TLSConfig.Clone()
		if config == nil {
			config = &tls.Config{}
		}
		if config.ServerName == "" {
			config.ServerName, _, _ = net.SplitHostPort(addr)
		}
		tlsConn := tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	return &dns.Conn{Conn: conn}, nil
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
		hasResolver = resolver != nil
		dnsdata     DNSData
		err         error
		// activeConn holds the AXFR connection dialed for the current attempt.
		// The transfer is read further down the loop body, so the connection
		// is closed at the top of the next iteration and via defer on return.
		// A deferred Close inside the loop only fires when queryMultiple
		// returns, so it would leak one socket per retry and per request type.
		activeConn *dns.Conn
	)
	defer func() {
		if activeConn != nil {
			_ = activeConn.Close()
		}
	}()

	// integrate data with known hosts in case
	if c.options.Hostsfile {
		if ips, ok := c.knownHosts[host]; ok {
			for _, ip := range ips {
				if iputil.IsIPv4(ip) {
					dnsdata.A = append(dnsdata.A, ip)
					if CheckInternalIPs && internalRangeCheckerInstance != nil {
						if parsedIP := net.ParseIP(ip); parsedIP != nil && internalRangeCheckerInstance.ContainsIPv4(parsedIP) {
							dnsdata.HasInternalIPs = true
							dnsdata.InternalIPs = append(dnsdata.InternalIPs, ip)
						}
					}
				} else if iputil.IsIPv6(ip) {
					dnsdata.AAAA = append(dnsdata.AAAA, ip)
					if CheckInternalIPs && internalRangeCheckerInstance != nil {
						if parsedIP := net.ParseIP(ip); parsedIP != nil && internalRangeCheckerInstance.ContainsIPv6(parsedIP) {
							dnsdata.HasInternalIPs = true
							dnsdata.InternalIPs = append(dnsdata.InternalIPs, ip)
						}
					}
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

		var i int
		for i = 0; i < c.options.MaxRetries; i++ {
			// These hold only this attempt's result.
			var (
				resp   *dns.Msg
				trResp chan *dns.Envelope
			)
			if activeConn != nil {
				_ = activeConn.Close()
				activeConn = nil
			}
			index := atomic.AddUint32(&c.serversIndex, 1)
			if !hasResolver {
				resolver = c.resolvers[index%uint32(len(c.resolvers))]
			}
			if r, ok := resolver.(*NetworkResolver); ok && requestType == dns.TypeAXFR {
				client := c.clientFor(r.Protocol)
				if client == nil {
					// zone transfers run over TCP, so it is the safe default
					client = c.tcpClient
				}
				var dnsconn *dns.Conn
				dnsconn, err = c.dial(client, resolver.String())
				if err == nil {
					activeConn = dnsconn
					dnsTransfer := &dns.Transfer{Conn: dnsconn}
					trResp, err = dnsTransfer.In(msg, resolver.String())
				}
			} else {
				resp, err = c.query(msg, resolver)
			}

			if err != nil || (trResp == nil && resp == nil) {
				continue
			}

			// https://github.com/projectdiscovery/retryabledns/issues/25
			if resp != nil && resp.Truncated && c.TCPFallback {
				resp, err = c.exchange(msg, TCP, resolver.String())
				if err != nil || resp == nil {
					continue
				}
			}

			// https://github.com/projectdiscovery/retryabledns/issues/250
			// When ExitOnStatusCodes is set, drop attempts whose rcode
			// is not in the list before they touch dnsdata. This keeps
			// dnsdata.Raw / dnsdata.Resolver / status fields free of
			// data from intermediate non-definitive responses.
			if resp != nil && len(c.options.ExitOnStatusCodes) > 0 && !c.options.exitOnRcode(resp.Rcode) {
				continue
			}

			// Parse what this attempt received. A DoH resolver answers a zone
			// transfer with a single reply, so AXFR doesn't imply a stream.
			if trResp != nil {
				err = dnsdata.ParseFromEnvelopeChan(trResp)
			} else {
				err = dnsdata.ParseFromMsg(resp)
			}

			// Note: this will refer only to the last valid response
			// the whole series of responses can be found in the dnsdata.Raw field
			dnsdata.RawResp = resp

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
				// An empty response can still be a definitive answer
				// (e.g. NXDOMAIN) when the user has opted into that via
				// ExitOnStatusCodes. Break so callers see the status
				// code without further retries polluting dnsdata.
				if len(c.options.ExitOnStatusCodes) > 0 && resp != nil && c.options.exitOnRcode(resp.Rcode) {
					break
				}
				continue
			}
			dnsdata.dedupe()

			// stop on a definitive rcode (success by default, or any of
			// the user-provided ExitOnStatusCodes)
			if resp != nil && c.options.exitOnRcode(resp.Rcode) {
				break
			}
			if trResp != nil {
				break
			}
		}
		// Finished retry loop at limit, bail out
		if i == c.options.MaxRetries && err != nil {
			err = errors.Join(ErrRetriesExceeded, err)
			break
		}
	}

	return &dnsdata, err
}

// QueryParallel sends a provided dns request to multiple resolvers in parallel.
// With both LocalAddrIP and LocalAddrPort set, queries that dial their own
// connection compete for that local port, so all but one may fail and come
// back empty.
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
			resp, err := c.query(msg.Copy(), parseResolver(resolver))
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

// Trace the requested domain with the provided query type, following referrals
// from the root servers. Besides its reply's answer, each step's NS lists the
// name servers that the reply referred to.
func (c *Client) Trace(host string, requestType uint16, maxrecursion int) (*TraceData, error) {
	var tracedata TraceData
	host = dns.CanonicalName(host)
	msg := dns.Msg{}
	msg.SetQuestion(host, requestType)
	servers := RootDNSServersIPv4
	seenNS := make(map[string]struct{})
	seenCName := make(map[string]int)
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

		var nsNames []string
		glue := make(map[string][]string)
		var nextCname string
		for _, d := range dnsdatas {
			// A referral lists the next name servers in the authority section,
			// which ParseFromMsg leaves out of d.NS
			names, addrs := referral(d.RawResp)
			d.NS = sliceutil.Dedupe(append(d.NS, names...))
			nsNames = append(nsNames, d.NS...)
			for name, ips := range addrs {
				glue[name] = append(glue[name], ips...)
			}
			// Follow CNAME - should happen at the final step of the trace
			for _, cname := range d.CNAME {
				if nextCname == "" {
					nextCname = cname
					break
				}
			}
		}
		// Every root server returns the same referral, so resolve each name
		// server once, from its glue when the referral has some
		var newNSResolvers []string
		for _, ns := range sliceutil.Dedupe(nsNames) {
			ips := glue[ns]
			if len(ips) == 0 {
				nsData, err := c.A(ns)
				if err != nil {
					continue
				}
				ips = nsData.A
			}
			for _, ip := range ips {
				newNSResolvers = append(newNSResolvers, net.JoinHostPort(ip, "53"))
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
			seenCName[nextCname]++
			if seenCName[nextCname] > c.options.MaxPerCNAMEFollows {
				break
			}
			host = nextCname
		}
	}

	return &tracedata, nil
}

// referral returns the name servers in msg's authority section, where a
// referral lists them, and the IPv4 glue that its additional section gives for
// them, keyed by name. Glue for any other name is left out.
func referral(msg *dns.Msg) (names []string, glue map[string][]string) {
	if msg == nil {
		return nil, nil
	}
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, trimChars(ns.Ns))
		}
	}
	glue = make(map[string][]string)
	for _, rr := range msg.Extra {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if name := trimChars(a.Hdr.Name); slices.Contains(names, name) {
			glue[name] = append(glue[name], a.A.String())
		}
	}
	return names, glue
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

	for _, r := range c.resolvers {
		if nr, ok := r.(*NetworkResolver); ok {
			resolvers = append(resolvers, &NetworkResolver{Protocol: TCP, Host: nr.Host, Port: nr.Port})
		}
	}

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
			// Per RFC 7208, a single TXT record can be broken up into multiple parts and "MUST be treated as if those strings are concatenated
			// together without adding spaces"; see: https://www.rfc-editor.org/rfc/rfc7208
			d.TXT = append(d.TXT, strings.Join(recordType.Txt, ""))
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
	return d.ParseFromRR(msg.Answer)
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
	d.SOA = d.dedupeSOA(d.SOA)
	d.CAA = sliceutil.Dedupe(d.CAA)
	d.AllRecords = sliceutil.Dedupe(d.AllRecords)
}

// dedupeSOA removes duplicate SOA records based on all fields
func (d *DNSData) dedupeSOA(soaRecords []SOA) []SOA {
	if len(soaRecords) <= 1 {
		return soaRecords
	}

	seen := make(map[string]struct{})
	var result []SOA

	for _, soa := range soaRecords {
		// Create a unique key based on all SOA fields
		key := fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d|%d",
			soa.Name, soa.NS, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)

		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, soa)
		}
	}

	return result
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
