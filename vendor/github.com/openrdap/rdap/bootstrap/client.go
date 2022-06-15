// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

// Package bootstrap implements an RDAP bootstrap client.
//
// All RDAP queries are handled by an RDAP server. To help clients discover
// RDAP servers, IANA publishes Service Registry files
// (https://data.iana.org/rdap) for several query types: Domain names, IP
// addresses, and Autonomous Systems.
//
// Given an RDAP query, this package finds the list of RDAP server URLs which
// can answer it. This includes downloading & parsing the Service Registry
// files.
//
// Basic usage:
//   question := &bootstrap.Question{
//     RegistryType: bootstrap.DNS,
//     Query: "example.cz",
//   }
//
//   b := &bootstrap.Client{}
//
//   var answer *bootstrap.Answer
//   answer, err := b.Lookup(question)
//
//   if err == nil {
//     for _, url := range answer.URLs {
//       fmt.Println(url)
//     }
//   }
//
// Download and list the contents of the DNS Service Registry:
//   b := &bootstrap.Client{}
//
//   // Before you can use a Registry, you need to download it first.
//   err := b.Download(bootstrap.DNS) // Downloads https://data.iana.org/rdap/dns.json.
//
//   if err == nil {
//     var dns *DNSRegistry = b.DNS()
//
//     // Print TLDs with RDAP service.
//     for tld, _ := range dns.File().Entries {
//       fmt.Println(tld)
//     }
//   }
//
// You can configure bootstrap.Client{} with a custom http.Client, base URL
// (default https://data.iana.org/rdap), and custom cache. bootstrap.Question{}
// support Contexts (for timeout, etc.).
//
// A bootstrap.Client caches the Service Registry files in memory for both
// performance, and courtesy to data.iana.org. The functions which make network
// requests are:
//   - Download()            - force download one of Service Registry file.
//   - DownloadWithContext() - force download one of Service Registry file.
//   - Lookup()              - download one Service Registry file if missing, or if the cached file is over (by default) 24 hours old.
//
// Lookup() is intended for repeated usage: A long lived bootstrap.Client will
// download each of {asn,dns,ipv4,ipv6}.json once per 24 hours only, regardless
// of the number of calls made to Lookup(). You can still refresh them manually
// using Download() if required.
//
// By default, Service Registry files are cached in memory. bootstrap.Client
// also supports caching the Service Registry files on disk. The default cache
// location is
// $HOME/.openrdap/.
//
// Disk cache usage:
//
//   b := bootstrap.NewClient()
//   b.Cache = cache.NewDiskCache()
//
//   dsr := b.DNS()  // Tries to load dns.json from disk cache, doesn't exist yet, so returns nil.
//   b.Download(bootstrap.DNS) // Downloads dns.json, saves to disk cache.
//
//   b2 := bootstrap.NewClient()
//   b2.Cache = cache.NewDiskCache()
//
//   dsr2 := b.DNS()  // Loads dns.json from disk cache.
//
// This package also implements the experimental Service Provider registry. Due
// to the experimental nature, no Service Registry file exists on data.iana.org
// yet, additionally the filename isn't known. The current filename used is
// serviceprovider-draft-03.json.
//
// RDAP bootstrapping is defined in https://tools.ietf.org/html/rfc7484.
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/openrdap/rdap/bootstrap/cache"
)

// A RegistryType represents a bootstrap registry type.
type RegistryType int

const (
	DNS RegistryType = iota
	IPv4
	IPv6
	ASN
	ServiceProvider
)

func (r RegistryType) String() string {
	switch r {
	case DNS:
		return "dns"
	case IPv4:
		return "ipv4"
	case IPv6:
		return "ipv6"
	case ASN:
		return "asn"
	case ServiceProvider:
		return "serviceprovider"
	default:
		panic("Unknown RegistryType")
	}
}

const (
	// Default URL of the Service Registry files.
	DefaultBaseURL = "https://data.iana.org/rdap/"

	// Default cache timeout of Service Registries.
	DefaultCacheTimeout = time.Hour * 24
)

// Client implements an RDAP bootstrap client.
type Client struct {
	HTTP    *http.Client        // HTTP client.
	BaseURL *url.URL            // Base URL of the Service Registry files. Default is DefaultBaseURL.
	Cache   cache.RegistryCache // Service Registry cache. Default is a MemoryCache.

	// Optional callback function for verbose messages.
	Verbose func(text string)

	registries map[RegistryType]Registry
}

// A Registry implements bootstrap lookups.
type Registry interface {
	Lookup(question *Question) (*Answer, error)
	File() *File
}

func (c *Client) init() {
	if c.HTTP == nil {
		c.HTTP = &http.Client{}
	}

	if c.Cache == nil {
		c.Cache = cache.NewMemoryCache()
		c.Cache.SetTimeout(DefaultCacheTimeout)
	}

	if c.registries == nil {
		c.registries = make(map[RegistryType]Registry)
	}

	if c.BaseURL == nil {
		c.BaseURL, _ = url.Parse(DefaultBaseURL)
	}
}

// Download downloads a single bootstrap registry file.
//
// On success, the relevant Registry is refreshed. Use the matching accessor (ASN(), DNS(), IPv4(), or IPv6()) to access it.
func (c *Client) Download(registry RegistryType) error {
	return c.DownloadWithContext(context.Background(), registry)
}

// DownloadWithContext downloads a single bootstrap registry file, with context |context|.
//
// On success, the relevant Registry is refreshed. Use the matching accessor (ASN(), DNS(), IPv4(), or IPv6()) to access it.
func (c *Client) DownloadWithContext(ctx context.Context, registry RegistryType) error {
	c.init()

	var json []byte
	var s Registry

	json, s, err := c.download(ctx, registry)

	if err != nil {
		return err
	}

	err = c.Cache.Save(c.filenameFor(registry), json)
	if err != nil {
		return err
	}

	c.registries[registry] = s

	return nil

}

func (c *Client) download(ctx context.Context, registry RegistryType) ([]byte, Registry, error) {
	u, err := url.Parse(registry.Filename())
	if err != nil {
		return nil, nil, err
	}

	baseURL := new(url.URL)
	*baseURL = *c.BaseURL

	if baseURL.Path != "" && baseURL.Path[len(baseURL.Path)-1] != '/' {
		baseURL.Path += "/"
	}

	var fetchURL *url.URL = baseURL.ResolveReference(u)
	req, err := http.NewRequest("GET", fetchURL.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req = req.WithContext(ctx)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("Server returned non-200 status code: %s", resp.Status)
	}

	json, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	var s Registry
	s, err = newRegistry(registry, json)

	if err != nil {
		return json, nil, err
	}

	return json, s, nil
}

func (c *Client) freshenFromCache(registry RegistryType) {
	if c.Cache.State(c.filenameFor(registry)) == cache.ShouldReload {
		c.reloadFromCache(registry)
	}
}

func (c *Client) reloadFromCache(registry RegistryType) error {
	json, err := c.Cache.Load(c.filenameFor(registry))

	if err != nil {
		return err
	}

	var s Registry
	s, err = newRegistry(registry, json)

	if err != nil {
		return err
	}

	c.registries[registry] = s

	return nil
}

func newRegistry(registry RegistryType, json []byte) (Registry, error) {
	var s Registry
	var err error

	switch registry {
	case ASN:
		s, err = NewASNRegistry(json)
	case DNS:
		s, err = NewDNSRegistry(json)
	case IPv4:
		s, err = NewNetRegistry(json, 4)
	case IPv6:
		s, err = NewNetRegistry(json, 6)
	case ServiceProvider:
		s, err = NewServiceProviderRegistry(json)
	default:
		panic("Unknown Registrytype")
	}

	return s, err
}

// Lookup returns the RDAP base URLs for the bootstrap question |question|.
func (c *Client) Lookup(question *Question) (*Answer, error) {
	c.init()
	if c.Verbose == nil {
		c.Verbose = func(text string) {}
	}

	c.Verbose("  bootstrap: Looking up...")
	c.Verbose(fmt.Sprintf("  bootstrap: Question type : %s", question.RegistryType))
	c.Verbose(fmt.Sprintf("  bootstrap: Question query: %s", question.Query))

	registry := question.RegistryType

	var state cache.FileState = c.Cache.State(c.filenameFor(registry))
	c.Verbose(fmt.Sprintf("  bootstrap: Cache state: %s: %s", c.filenameFor(registry), state))

	var forceDownload bool
	if state == cache.ShouldReload {
		if err := c.reloadFromCache(registry); err != nil {
			forceDownload = true

			c.Verbose(fmt.Sprintf("  bootstrap: Cache load error (%s), downloading...", err))
		}
	}

	if c.registries[registry] == nil || forceDownload {
		c.Verbose(fmt.Sprintf("  bootstrap: Downloading %s", registry.Filename()))

		err := c.DownloadWithContext(question.Context(), registry)
		if err != nil {
			return nil, err
		}
	} else {
		c.Verbose("  bootstrap: Using cached Service Registry file")
	}

	answer, err := c.registries[registry].Lookup(question)

	if answer != nil {
		c.Verbose(fmt.Sprintf("  bootstrap: Looked up '%s'", answer.Query))
		if answer.Entry != "" {
			c.Verbose(fmt.Sprintf("  bootstrap: Matching entry '%s'", answer.Entry))
		} else {
			c.Verbose(fmt.Sprintf("  bootstrap: No match"))
		}

		for i, url := range answer.URLs {
			c.Verbose(fmt.Sprintf("  bootstrap: Service URL #%d: '%s'", i+1, url))
		}
	}

	return answer, err
}

// ASN returns the current ASN Registry (or nil if the registry file hasn't been Download()ed).
//
// This function never initiates a network transfer.
func (c *Client) ASN() *ASNRegistry {
	c.init()
	c.freshenFromCache(ServiceProvider)

	s, _ := c.registries[ASN].(*ASNRegistry)
	return s
}

//
// DNS returns the current DNS Registry (or nil if the registry file hasn't been Download()ed).
//
// This function never initiates a network transfer.
func (c *Client) DNS() *DNSRegistry {
	c.init()
	c.freshenFromCache(ServiceProvider)

	s, _ := c.registries[DNS].(*DNSRegistry)
	return s
}

// IPv4 returns the current IPv4 Registry (or nil if the registry file hasn't been Download()ed).
//
// This function never initiates a network transfer.
func (c *Client) IPv4() *NetRegistry {
	c.init()
	c.freshenFromCache(ServiceProvider)

	s, _ := c.registries[IPv4].(*NetRegistry)
	return s
}

// IPv6 returns the current IPv6 Registry (or nil if the registry file hasn't been Download()ed).
//
// This function never initiates a network transfer.
func (c *Client) IPv6() *NetRegistry {
	c.init()
	c.freshenFromCache(ServiceProvider)

	s, _ := c.registries[IPv6].(*NetRegistry)
	return s
}

// ServiceProvider returns the current ServiceProvider Registry (or nil if the registry file hasn't been Download()ed).
//
// This function never initiates a network transfer.
func (c *Client) ServiceProvider() *ServiceProviderRegistry {
	c.init()
	c.freshenFromCache(ServiceProvider)

	s, _ := c.registries[ServiceProvider].(*ServiceProviderRegistry)
	return s
}

// fileFor returns a filename to save the bootstrap registry file |r| as.
//
// For the official IANA bootstrap service, this is the exact filename, e.g.
// dns.json.
//
// For custom bootstrap services, a 6 character hash of the bootstrap service
// URL is prepended to the filename (e.g. 012def_dns.json), to prevent mixing
// them up.
func (c *Client) filenameFor(r RegistryType) string {
	filename := r.Filename()

	if c.BaseURL.String() != DefaultBaseURL {
		hasher := sha256.New()
		hasher.Write([]byte(c.BaseURL.String()))
		sha256Hash := hex.EncodeToString(hasher.Sum(nil))

		filename = sha256Hash[0:6] + "_" + filename
	}

	return filename
}

// Filename returns the JSON document filename: One of {asn,dns,ipv4,ipv6,service_provider}.json.
func (r RegistryType) Filename() string {
	switch r {
	case ASN:
		return "asn.json"
	case DNS:
		return "dns.json"
	case IPv4:
		return "ipv4.json"
	case IPv6:
		return "ipv6.json"
	case ServiceProvider:
		// This is a guess and will need fixing to match whatever IANA chooses.
		return "serviceprovider-draft-03.json"
	default:
		panic("Unknown RegistryType")
	}
}
