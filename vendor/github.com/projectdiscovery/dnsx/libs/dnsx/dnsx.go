package dnsx

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/cdncheck"
	retryabledns "github.com/projectdiscovery/retryabledns"
	iputil "github.com/projectdiscovery/utils/ip"
)

// DNSX is structure to perform dns lookups
type DNSX struct {
	dnsClient *retryabledns.Client
	Options   *Options
	cdn       *cdncheck.Client
}

// Options contains configuration options
type Options struct {
	BaseResolvers     []string
	MaxRetries        int
	QuestionTypes     []uint16
	Trace             bool
	TraceMaxRecursion int
	Hostsfile         bool
	OutputCDN         bool
}

// ResponseData to show output result
type ResponseData struct {
	*retryabledns.DNSData
	IsCDNIP bool         `json:"cdn,omitempty" csv:"cdn"`
	CDNName string       `json:"cdn-name,omitempty" csv:"cdn-name"`
	ASN     *AsnResponse `json:"asn,omitempty" csv:"asn"`
}
type AsnResponse struct {
	AsNumber  string   `json:"as-number,omitempty" csv:"as_number"`
	AsName    string   `json:"as-name,omitempty" csv:"as_name"`
	AsCountry string   `json:"as-country,omitempty" csv:"as_country"`
	AsRange   []string `json:"as-range,omitempty" csv:"as_range"`
}

func (o *AsnResponse) String() string {
	return fmt.Sprintf("[%v, %v, %v]", o.AsNumber, o.AsName, o.AsCountry)
}

func (d *ResponseData) JSON() (string, error) {
	b, err := json.Marshal(&d)
	return string(b), err
}

// DefaultOptions contains the default configuration options
var DefaultOptions = Options{
	BaseResolvers:     DefaultResolvers,
	MaxRetries:        5,
	QuestionTypes:     []uint16{miekgdns.TypeA},
	TraceMaxRecursion: math.MaxUint16,
	Hostsfile:         true,
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"udp:1.1.1.1:53", // Cloudflare
	"udp:1.0.0.1:53", // Cloudflare
	"udp:8.8.8.8:53", // Google
	"udp:8.8.4.4:53", // Google
}

// New creates a dns resolver
func New(options Options) (*DNSX, error) {
	retryablednsOptions := retryabledns.Options{
		BaseResolvers: options.BaseResolvers,
		MaxRetries:    options.MaxRetries,
		Hostsfile:     options.Hostsfile,
	}

	dnsClient, err := retryabledns.NewWithOptions(retryablednsOptions)
	if err != nil {
		return nil, err
	}
	dnsClient.TCPFallback = true
	dnsx := &DNSX{dnsClient: dnsClient, Options: &options}
	if options.OutputCDN {
		dnsx.cdn = cdncheck.New()
	}
	return dnsx, nil
}

// Lookup performs a DNS A question and returns corresponding IPs
func (d *DNSX) Lookup(hostname string) ([]string, error) {
	if iputil.IsIP(hostname) {
		return []string{hostname}, nil
	}

	dnsdata, err := d.dnsClient.Resolve(hostname)
	if err != nil {
		return nil, err
	}

	if dnsdata == nil || len(dnsdata.A) == 0 {
		return []string{}, errors.New("no ips found")
	}

	return dnsdata.A, nil
}

// QueryOne performs a DNS question of a specified type and returns raw responses
func (d *DNSX) QueryOne(hostname string) (*retryabledns.DNSData, error) {
	return d.dnsClient.Query(hostname, d.Options.QuestionTypes[0])
}

// QueryMultiple performs a DNS question of the specified types and returns raw responses
func (d *DNSX) QueryMultiple(hostname string) (*retryabledns.DNSData, error) {
	return d.dnsClient.QueryMultiple(hostname, d.Options.QuestionTypes)
}

// Trace performs a DNS trace of the specified types and returns raw responses
func (d *DNSX) Trace(hostname string) (*retryabledns.TraceData, error) {
	return d.dnsClient.Trace(hostname, d.Options.QuestionTypes[0], d.Options.TraceMaxRecursion)
}

// Trace performs a DNS trace of the specified types and returns raw responses
func (d *DNSX) AXFR(hostname string) (*retryabledns.AXFRData, error) {
	return d.dnsClient.AXFR(hostname)
}
