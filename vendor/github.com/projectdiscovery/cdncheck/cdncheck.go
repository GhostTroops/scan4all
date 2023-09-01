package cdncheck

import (
	"net"
	"strings"
	"sync"

	"github.com/projectdiscovery/retryabledns"
)

var (
	DefaultCDNProviders   string
	DefaultWafProviders   string
	DefaultCloudProviders string
)

// DefaultResolvers trusted (taken from fastdialer)
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	sync.Once
	cdn          *providerScraper
	waf          *providerScraper
	cloud        *providerScraper
	retriabledns *retryabledns.Client
}

// New creates cdncheck client with default options
// NewWithOpts should be preferred over this function
func New() *Client {
	client, _ := NewWithOpts(3, []string{})
	return client
}

// NewWithOpts creates cdncheck client with custom options
func NewWithOpts(MaxRetries int, resolvers []string) (*Client, error) {
	if MaxRetries <= 0 {
		MaxRetries = 3
	}
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	retryabledns, err := retryabledns.New(resolvers, MaxRetries)
	if err != nil {
		return nil, err
	}
	client := &Client{
		cdn:          newProviderScraper(generatedData.CDN),
		waf:          newProviderScraper(generatedData.WAF),
		cloud:        newProviderScraper(generatedData.Cloud),
		retriabledns: retryabledns,
	}
	return client, nil
}

// CheckCDN checks if an IP is contained in the cdn denylist
func (c *Client) CheckCDN(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cdn.Match(ip)
	return matched, value, err
}

// CheckWAF checks if an IP is contained in the waf denylist
func (c *Client) CheckWAF(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.waf.Match(ip)
	return matched, value, err
}

// CheckCloud checks if an IP is contained in the cloud denylist
func (c *Client) CheckCloud(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cloud.Match(ip)
	return matched, value, err
}

// Check checks if ip belongs to one of CDN, WAF and Cloud . It is generic method for Checkxxx methods
func (c *Client) Check(ip net.IP) (matched bool, value string, itemType string, err error) {
	if matched, value, err = c.cdn.Match(ip); err == nil && matched && value != "" {
		return matched, value, "cdn", nil
	}
	if matched, value, err = c.waf.Match(ip); err == nil && matched && value != "" {
		return matched, value, "waf", nil
	}
	if matched, value, err = c.cloud.Match(ip); err == nil && matched && value != "" {
		return matched, value, "cloud", nil
	}
	return false, "", "", err
}

// Check Domain with fallback checks if domain belongs to one of CDN, WAF and Cloud . It is generic method for Checkxxx methods
// Since input is domain, as a fallback it queries CNAME records and checks if domain is WAF
func (c *Client) CheckDomainWithFallback(domain string) (matched bool, value string, itemType string, err error) {
	dnsData, err := c.retriabledns.Resolve(domain)
	if err != nil {
		return false, "", "", err
	}
	matched, value, itemType, err = c.CheckDNSResponse(dnsData)
	if err != nil {
		return false, "", "", err
	}
	if matched {
		return matched, value, itemType, nil
	}
	// resolve cname
	dnsData, err = c.retriabledns.CNAME(domain)
	if err != nil {
		return false, "", "", err
	}
	return c.CheckDNSResponse(dnsData)
}

// CheckDNSResponse is same as CheckDomainWithFallback but takes DNS response as input
func (c *Client) CheckDNSResponse(dnsResponse *retryabledns.DNSData) (matched bool, value string, itemType string, err error) {
	if dnsResponse.A != nil {
		for _, ip := range dnsResponse.A {
			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				continue
			}
			matched, value, itemType, err := c.Check(ipAddr)
			if err != nil {
				return false, "", "", err
			}
			if matched {
				return matched, value, itemType, nil
			}
		}
	}
	if dnsResponse.CNAME != nil {
		matched, discovered, itemType, err := c.CheckSuffix(dnsResponse.CNAME...)
		if err != nil {
			return false, "", itemType, err
		}
		if matched {
			// for now checkSuffix only checks for wafs
			return matched, discovered, itemType, nil
		}
	}
	return false, "", "", err
}

func mapKeys(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
