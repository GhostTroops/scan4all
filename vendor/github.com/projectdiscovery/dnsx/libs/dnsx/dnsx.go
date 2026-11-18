package dnsx

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/cdncheck"
	retryabledns "github.com/projectdiscovery/retryabledns"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
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
	QueryAll          bool
	Proxy             string
	Timeout           time.Duration
}

// ResponseData to show output result
type ResponseData struct {
	*retryabledns.DNSData
	IsCDNIP   bool         `json:"cdn,omitempty" csv:"cdn"`
	CDNName   string       `json:"cdn-name,omitempty" csv:"cdn-name"`
	CDNType   string       `json:"cdn-type,omitempty" csv:"cdn-type"`
	ASN       *AsnResponse `json:"asn,omitempty" csv:"asn"`
	QueryTime string       `json:"query-time,omitempty" csv:"query-time"`
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

type MarshalOption func(d *ResponseData)

func WithoutAllRecords() MarshalOption {
	return func(d *ResponseData) {
		d.AllRecords = nil
	}
}

func (d *ResponseData) JSON(options ...MarshalOption) (string, error) {
	dataToMarshal := *d
	// Always remove RawResp from JSON output as it's redundant and bloats the output
	dataToMarshal.RawResp = nil
	for _, option := range options {
		option(&dataToMarshal)
	}
	b, err := json.Marshal(dataToMarshal)
	return string(b), err
}

// DefaultOptions contains the default configuration options
var DefaultOptions = Options{
	BaseResolvers:     DefaultResolvers,
	MaxRetries:        5,
	QuestionTypes:     []uint16{miekgdns.TypeA},
	TraceMaxRecursion: 255,
	Hostsfile:         true,
	Timeout:           3 * time.Second,
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"udp:1.1.1.1:53",         // Cloudflare
	"udp:1.0.0.1:53",         // Cloudflare
	"udp:8.8.8.8:53",         // Google
	"udp:8.8.4.4:53",         // Google
	"udp:9.9.9.9:53",         // Quad9
	"udp:149.112.112.112:53", // Quad9
	"udp:208.67.222.222:53",  // Open DNS
	"udp:208.67.220.220:53",  // Open DNS
}

// New creates a dns resolver
func New(options Options) (*DNSX, error) {
	retryablednsOptions := retryabledns.Options{
		BaseResolvers: options.BaseResolvers,
		MaxRetries:    options.MaxRetries,
		Hostsfile:     options.Hostsfile,
		Proxy:         options.Proxy,
		Timeout:       options.Timeout,
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
	// Omit PTR queries unless the input is an IP address to decrease execution time, as PTR queries can lead to timeouts.
	filteredQuestionTypes := d.Options.QuestionTypes
	if d.Options.QueryAll {
		isIP := iputil.IsIP(hostname)
		if !isIP {
			filteredQuestionTypes = sliceutil.PruneEqual(filteredQuestionTypes, miekgdns.TypePTR)
		} else {
			filteredQuestionTypes = []uint16{miekgdns.TypePTR}
		}
	}
	return d.dnsClient.QueryMultiple(hostname, filteredQuestionTypes)
}

// Trace performs a DNS trace of the specified types and returns raw responses
func (d *DNSX) Trace(hostname string) (*retryabledns.TraceData, error) {
	if len(d.Options.QuestionTypes) == 0 {
		return nil, errors.New("no question types specified for trace")
	}
	return d.dnsClient.Trace(hostname, d.Options.QuestionTypes[0], d.Options.TraceMaxRecursion)
}

// Trace performs a DNS trace of the specified types and returns raw responses
func (d *DNSX) AXFR(hostname string) (*retryabledns.AXFRData, error) {
	return d.dnsClient.AXFR(hostname)
}
