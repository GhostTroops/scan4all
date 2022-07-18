package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/stringsutil"
)

// DNSServer is a DNS server instance that listens on port 53.
type DNSServer struct {
	options    *Options
	mxDomains  map[string]string
	nsDomains  map[string][]string
	ipAddress  net.IP
	timeToLive uint32
	server     *dns.Server
	TxtRecord  string // used for ACME verification
}

// NewDNSServer returns a new DNS server.
func NewDNSServer(network string, options *Options) *DNSServer {
	mxDomains := make(map[string]string)
	nsDomains := make(map[string][]string)

	for _, domain := range options.Domains {
		dotdomain := dns.Fqdn(domain)

		mxDomain := fmt.Sprintf("mail.%s", dotdomain)
		mxDomains[dotdomain] = mxDomain

		ns1Domain := fmt.Sprintf("ns1.%s", dotdomain)
		ns2Domain := fmt.Sprintf("ns2.%s", dotdomain)
		nsDomains[dotdomain] = []string{ns1Domain, ns2Domain}

	}

	server := &DNSServer{
		options:    options,
		ipAddress:  net.ParseIP(options.IPAddress),
		mxDomains:  mxDomains,
		nsDomains:  nsDomains,
		timeToLive: 3600,
	}
	server.server = &dns.Server{
		Addr:    options.ListenIP + fmt.Sprintf(":%d", options.DnsPort),
		Net:     network,
		Handler: server,
	}
	return server
}

// ListenAndServe listens on dns ports for the server.
func (h *DNSServer) ListenAndServe(dnsAlive chan bool) {
	dnsAlive <- true
	if err := h.server.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not listen for %s DNS on %s (%s)\n", strings.ToUpper(h.server.Net), h.server.Addr, err)
		dnsAlive <- false
	}
}

const (
	dnsChallengeString   = "_acme-challenge."
	certificateAuthority = "letsencrypt.org."
)

// ServeDNS is the default handler for DNS queries.
func (h *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// bail early for no queries.
	if len(r.Question) == 0 {
		return
	}

	isDNSChallenge := false
	for _, question := range r.Question {
		domain := question.Name

		// Handle DNS server cases for ACME server
		if strings.HasPrefix(strings.ToLower(domain), dnsChallengeString) {
			isDNSChallenge = true

			gologger.Debug().Msgf("Got acme dns request: \n%s\n", r.String())

			switch question.Qtype {
			case dns.TypeSOA:
				h.handleSOA(domain, m)
			case dns.TypeTXT:
				err := h.handleACMETXTChallenge(domain, m)
				if err != nil {
					fmt.Printf("handleACMETXTChallenge for zone %s err: %+v\n", domain, err)
					return
				}
			case dns.TypeNS:
				h.handleNS(domain, m)
			case dns.TypeA, dns.TypeAAAA:
				h.handleACNAMEANY(domain, m)
			}

			gologger.Debug().Msgf("Got acme dns response: \n%s\n", m.String())
		} else {
			switch question.Qtype {
			case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeANY:
				h.handleACNAMEANY(domain, m)
			case dns.TypeMX:
				h.handleMX(domain, m)
			case dns.TypeNS:
				h.handleNS(domain, m)
			case dns.TypeSOA:
				h.handleSOA(domain, m)
			case dns.TypeTXT:
				h.handleTXT(domain, m)
			}
		}
	}
	if !isDNSChallenge {
		// Write interaction for first question and dns request
		h.handleInteraction(r.Question[0].Name, w, r, m)
	}

	if err := w.WriteMsg(m); err != nil {
		gologger.Warning().Msgf("Could not write DNS response: \n%s\n %s\n", m.String(), err)
	}
}

// handleACMETXTChallenge handles solving of ACME TXT challenge with the given provider
func (h *DNSServer) handleACMETXTChallenge(zone string, m *dns.Msg) error {
	records, err := h.options.ACMEStore.GetRecords(context.Background(), strings.ToLower(zone))
	if err != nil {
		return err
	}

	rrs := []dns.RR{}
	for _, record := range records {
		txtHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(record.TTL)}
		rrs = append(rrs, &dns.TXT{Hdr: txtHdr, Txt: []string{record.Value}})
	}
	m.Answer = append(m.Answer, rrs...)
	return nil
}

// handleACNAMEANY handles A, CNAME or ANY queries for DNS server
func (h *DNSServer) handleACNAMEANY(zone string, m *dns.Msg) {
	nsHeader := dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}

	resultFunction := func(zone string, ipAddress net.IP) {
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: ipAddress})
		dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
		for _, dotDomain := range dotDomains {
			if nsDomains, ok := h.nsDomains[dotDomain]; ok {
				for _, nsDomain := range nsDomains {
					m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: nsDomain})
					m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: nsDomain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
				}
				return
			}
		}
	}

	dotDomain := dns.Fqdn(h.options.Domains[0])
	for _, domain := range h.options.Domains {
		configuredDotDomain := dns.Fqdn(domain)
		if dns.Fqdn(domain) == zone {
			dotDomain = configuredDotDomain
			break
		}
	}

	switch {
	case strings.EqualFold(zone, "aws"+dotDomain):
		resultFunction(zone, net.ParseIP("169.254.169.254"))
	case strings.EqualFold(zone, "alibaba"+dotDomain):
		resultFunction(zone, net.ParseIP("100.100.100.200"))
	default:
		resultFunction(zone, h.ipAddress)
	}
}

func (h *DNSServer) handleMX(zone string, m *dns.Msg) {
	nsHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: h.timeToLive}

	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if mxdomain, ok := h.mxDomains[dotDomain]; ok {
			m.Answer = append(m.Answer, &dns.MX{Hdr: nsHdr, Mx: mxdomain, Preference: 1})
			return
		}
	}
}

func (h *DNSServer) handleNS(zone string, m *dns.Msg) {
	nsHeader := dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}

	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if nsDomains, ok := h.nsDomains[dotDomain]; ok {
			for _, nsDomain := range nsDomains {
				m.Answer = append(m.Answer, &dns.NS{Hdr: nsHeader, Ns: nsDomain})
			}
			return
		}
	}
}

func (h *DNSServer) handleSOA(zone string, m *dns.Msg) {
	nsHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET}
	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if nsDomains, ok := h.nsDomains[dotDomain]; ok {
			for _, nsDomain := range nsDomains {
				m.Answer = append(m.Answer, &dns.SOA{Hdr: nsHdr, Ns: nsDomain, Mbox: certificateAuthority, Serial: 1, Expire: 60, Minttl: 60})
				return
			}
		}
	}
}

func (h *DNSServer) handleTXT(zone string, m *dns.Msg) {
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{h.TxtRecord}})
}

func toQType(ttype uint16) (rtype string) {
	switch ttype {
	case dns.TypeA:
		rtype = "A"
	case dns.TypeNS:
		rtype = "NS"
	case dns.TypeCNAME:
		rtype = "CNAME"
	case dns.TypeSOA:
		rtype = "SOA"
	case dns.TypePTR:
		rtype = "PTR"
	case dns.TypeMX:
		rtype = "MX"
	case dns.TypeTXT:
		rtype = "TXT"
	case dns.TypeAAAA:
		rtype = "AAAA"
	}
	return
}

// handleInteraction handles an interaction for the DNS server
func (h *DNSServer) handleInteraction(domain string, w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) {
	var uniqueID, fullID string

	requestMsg := r.String()
	responseMsg := m.String()

	gologger.Debug().Msgf("New DNS request: %s\n", requestMsg)

	var foundDomain string
	for _, configuredDomain := range h.options.Domains {
		configuredDotDomain := dns.Fqdn(configuredDomain)
		if stringsutil.HasSuffixI(domain, configuredDotDomain) {
			foundDomain = configuredDomain
			break
		}
	}

	// if root-tld is enabled stores any interaction towards the main domain
	if h.options.RootTLD && foundDomain != "" {
		correlationID := foundDomain
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		interaction := &Interaction{
			Protocol:      "dns",
			UniqueID:      domain,
			FullId:        domain,
			QType:         toQType(r.Question[0].Qtype),
			RawRequest:    requestMsg,
			RawResponse:   responseMsg,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode root tld dns interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("Root TLD DNS Interaction: \n%s\n", buffer.String())
			if err := h.options.Storage.AddInteractionWithId(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
			}
		}
	}

	if foundDomain != "" {
		parts := strings.Split(domain, ".")
		for i, part := range parts {
			if h.options.isCorrelationID(part) {
				uniqueID = part
				fullID = part
				if i+1 <= len(parts) {
					fullID = strings.Join(parts[:i+1], ".")
				}
			}
		}
	}
	uniqueID = strings.ToLower(uniqueID)

	if uniqueID != "" {
		correlationID := uniqueID[:h.options.CorrelationIdLength]
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		interaction := &Interaction{
			Protocol:      "dns",
			UniqueID:      uniqueID,
			FullId:        fullID,
			QType:         toQType(r.Question[0].Qtype),
			RawRequest:    requestMsg,
			RawResponse:   responseMsg,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode dns interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("DNS Interaction: \n%s\n", buffer.String())
			if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
			}
		}
	}
}
