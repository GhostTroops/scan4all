package cdncheck

import (
	"net"

	"github.com/yl2chen/cidranger"
)

// InputCompiled contains a compiled list of input structure
type InputCompiled struct {
	// CDN contains a list of ranges for CDN cidrs
	CDN map[string][]string `yaml:"cdn,omitempty" json:"cdn,omitempty"`
	// WAF contains a list of ranges for WAF cidrs
	WAF map[string][]string `yaml:"waf,omitempty" json:"waf,omitempty"`
	// Cloud contains a list of ranges for Cloud cidrs
	Cloud map[string][]string `yaml:"cloud,omitempty" json:"cloud,omitempty"`
	// Common contains a list of suffixes for major sources
	Common map[string][]string `yaml:"common,omitempty" json:"common,omitempty"`
}

// providerScraper is a structure for scraping providers
type providerScraper struct {
	rangers map[string]cidranger.Ranger
}

// newProviderScraper returns a new provider scraper instance
func newProviderScraper(ranges map[string][]string) *providerScraper {
	scraper := &providerScraper{rangers: make(map[string]cidranger.Ranger)}

	for provider, items := range ranges {
		ranger := cidranger.NewPCTrieRanger()
		for _, cidr := range items {
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				_ = ranger.Insert(cidranger.NewBasicRangerEntry(*network))
			}
		}
		scraper.rangers[provider] = ranger
	}
	return scraper
}

// Match returns true if the IP matches provided CIDR ranges
func (p *providerScraper) Match(ip net.IP) (bool, string, error) {
	for provider, ranger := range p.rangers {
		if contains, err := ranger.Contains(ip); contains {
			return true, provider, err
		}
	}
	return false, "", nil
}
