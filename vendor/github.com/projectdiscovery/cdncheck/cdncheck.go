package cdncheck

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/yl2chen/cidranger"
)

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	Options *Options
	ranges  map[string][]string
	rangers map[string]cidranger.Ranger
}

var defaultScrapers = map[string]scraperFunc{
	"azure":      scrapeAzure,
	"cloudflare": scrapeCloudflare,
	"cloudfront": scrapeCloudFront,
	"fastly":     scrapeFastly,
	"incapsula":  scrapeIncapsula,
}

var defaultScrapersWithOptions = map[string]scraperWithOptionsFunc{
	"akamai":   scrapeAkamai,
	"sucuri":   scrapeSucuri,
	"leaseweb": scrapeLeaseweb,
}

// New creates a new firewall IP checking client.
func New() (*Client, error) {
	return new(&Options{})
}

// NewWithCache creates a new firewall IP with cached data from project discovery (faster)
func NewWithCache() (*Client, error) {
	return new(&Options{Cache: true})
}

// NewWithOptions creates a new instance with options
func NewWithOptions(Options *Options) (*Client, error) {
	return new(Options)
}

func new(options *Options) (*Client, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSClientConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(30) * time.Second,
	}
	client := &Client{Options: options}

	var err error
	if options.Cache {
		err = client.getCDNDataFromCache(httpClient)
	} else {
		err = client.getCDNData(httpClient)
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) getCDNData(httpClient *http.Client) error {
	c.ranges = make(map[string][]string)
	c.rangers = make(map[string]cidranger.Ranger)
	for provider, scraper := range defaultScrapers {
		cidrs, err := scraper(httpClient)
		if err != nil {
			return err
		}

		c.ranges[provider] = cidrs
		ranger := cidranger.NewPCTrieRanger()
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			_ = ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		c.rangers[provider] = ranger
	}
	if c.Options.HasAuthInfo() {
		for provider, scraper := range defaultScrapersWithOptions {
			cidrs, err := scraper(httpClient, c.Options)
			if err != nil {
				return err
			}

			c.ranges[provider] = cidrs
			ranger := cidranger.NewPCTrieRanger()
			for _, cidr := range cidrs {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				_ = ranger.Insert(cidranger.NewBasicRangerEntry(*network))
			}
			c.rangers[provider] = ranger
		}
	}
	return nil
}

func (c *Client) getCDNDataFromCache(httpClient *http.Client) error {
	var err error
	c.ranges, err = scrapeProjectDiscovery(httpClient)
	if err != nil {
		return err
	}

	c.rangers = make(map[string]cidranger.Ranger)
	for provider, ranges := range c.ranges {
		ranger := cidranger.NewPCTrieRanger()

		for _, cidr := range ranges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			_ = ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		c.rangers[provider] = ranger
	}
	return nil
}

// Check checks if an IP is contained in the blacklist
func (c *Client) Check(ip net.IP) (bool, string, error) {
	for provider, ranger := range c.rangers {
		if contains, err := ranger.Contains(ip); contains {
			return true, provider, err
		}
	}
	return false, "", nil
}

// Ranges returns the providers and ranges for the cdn client
func (c *Client) Ranges() map[string][]string {
	return c.ranges
}
