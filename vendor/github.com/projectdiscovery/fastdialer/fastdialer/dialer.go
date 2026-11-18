package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Mzack9999/gcache"
	gounit "github.com/docker/go-units"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/retryabledns"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	"github.com/projectdiscovery/utils/env"
	"github.com/zmap/zcrypto/encoding/asn1"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/proxy"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/fastdialer/fastdialer/metafiles"
	"github.com/projectdiscovery/fastdialer/fastdialer/utils"
)

// option to disable ztls fallback in case of handshake error
// reads from env variable DISABLE_ZTLS_FALLBACK
var (
	disableZTLSFallback = false
	MaxDNSCacheSize     int64
	MaxDNSItems         = 1024
	MaxDialCacheSize    = 10000
)

func init() {
	// enable permissive parsing for ztls, so that it can allow permissive parsing for X509 certificates
	asn1.AllowPermissiveParsing = true
	disableZTLSFallback = env.GetEnvOrDefault("DISABLE_ZTLS_FALLBACK", false)
	maxCacheSize := env.GetEnvOrDefault("MAX_DNS_CACHE_SIZE", "10mb")
	maxDnsCacheSize, err := gounit.FromHumanSize(maxCacheSize)
	if err != nil {
		panic(err)
	}
	MaxDNSCacheSize = maxDnsCacheSize
	MaxDNSItems = env.GetEnvOrDefault("MAX_DNS_ITEMS", 1024)

	// Register DNS types with gob encoder
	gob.Register(&dns.SOA{})
	gob.Register(&dns.A{})
	gob.Register(&dns.AAAA{})
	gob.Register(&dns.CNAME{})
	gob.Register(&dns.MX{})
	gob.Register(&dns.NS{})
	gob.Register(&dns.PTR{})
	gob.Register(&dns.SRV{})
	gob.Register(&dns.TXT{})
	gob.Register(&dns.CAA{})
	gob.Register(&dns.DNSKEY{})
	gob.Register(&dns.DS{})
	gob.Register(&dns.NSEC{})
	gob.Register(&dns.NSEC3{})
	gob.Register(&dns.RRSIG{})
	gob.Register(&dns.TLSA{})
	gob.Register(&dns.OPT{})
}

// Dialer structure containing data information
type Dialer struct {
	options   *Options
	dnsclient *retryabledns.Client
	// memory typed cache
	mDnsCache gcache.Cache[string, *retryabledns.DNSData]
	// memory/disk untyped ([]byte) cache
	hmDnsCache        *hybrid.HybridMap
	hostsFileData     *hybrid.HybridMap
	dialerHistory     *hybrid.HybridMap
	dialerTLSData     *hybrid.HybridMap
	dialer            *net.Dialer
	proxyDialer       *proxy.Dialer
	networkpolicy     *networkpolicy.NetworkPolicy
	searchDomains     []string
	ndots             int
	dialCache         gcache.Cache[string, *utils.DialWrap]
	dialTimeoutErrors gcache.Cache[string, *atomic.Uint32]

	resolutionsGroup *singleflight.Group
}

// NewDialer instance
func NewDialer(options Options) (*Dialer, error) {
	var resolvers []string
	var searchDomains []string
	var ndots = options.Ndots
	if ndots <= 0 {
		ndots = DefaultNdots
	}

	// Add system resolvers as the first to be tried
	if options.ResolversFile {
		systemConfig, err := loadResolverFile(options)
		if err == nil && systemConfig != nil {
			if len(systemConfig.Resolvers) > 0 {
				resolvers = systemConfig.Resolvers
			}

			if len(systemConfig.SearchDomains) > 0 {
				searchDomains = systemConfig.SearchDomains
			}

			if systemConfig.Ndots > 0 {
				ndots = systemConfig.Ndots
			}
		}
	}

	resolvers = append(resolvers, options.BaseResolvers...)
	var err error
	var dialerHistory *hybrid.HybridMap
	if options.WithDialerHistory {
		// we need to use disk to store all the dialed ips
		dialerHistoryCacheOptions := hybrid.DefaultDiskOptions
		dialerHistoryCacheOptions.DBType = getHMAPDBType(options)
		dialerHistory, err = hybrid.New(dialerHistoryCacheOptions)
		if err != nil {
			return nil, err
		}
	}
	// when loading in memory set max size to 10 MB
	var (
		hmDnsCache *hybrid.HybridMap
		dnsCache   gcache.Cache[string, *retryabledns.DNSData]
	)

	switch options.CacheType {
	case Hybrid, Disk:
		hmDnsCache, err = hybrid.New(hybrid.DefaultHybridOptions)
		if err != nil {
			return nil, err
		}
	default: // Memory
		dnsCache = gcache.New[string, *retryabledns.DNSData](MaxDNSItems).Build()
	}

	var dialerTLSData *hybrid.HybridMap
	if options.WithTLSData {
		dialerTLSData, err = hybrid.New(hybrid.DefaultDiskOptions)
		if err != nil {
			return nil, err
		}
	}

	var dialer *net.Dialer
	if options.Dialer != nil {
		dialer = options.Dialer
	} else {
		dialer = &net.Dialer{
			Timeout:   options.DialerTimeout,
			KeepAlive: options.DialerKeepAlive,
		}
	}

	var hostsFileData *hybrid.HybridMap
	// load hardcoded values from host file
	if options.HostsFile {
		var err error
		if options.CacheType == Memory {
			hostsFileData, err = metafiles.GetHostsFileDnsData(metafiles.InMemory)
		} else {
			hostsFileData, err = metafiles.GetHostsFileDnsData(metafiles.Hybrid)
		}
		if options.Logger != nil && err != nil {
			options.Logger.Printf("could not load hosts file: %s\n", err)
		}
	}
	dnsclient, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: resolvers,
		MaxRetries:    options.MaxRetries,
		Timeout:       1 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	var np *networkpolicy.NetworkPolicy
	if options.NetworkPolicy != nil {
		np = options.NetworkPolicy
	} else {
		np, err = createNetworkPolicy(options)
		if err != nil {
			return nil, fmt.Errorf("could not create network policy: %w", err)
		}
	}

	d := &Dialer{
		dnsclient:        dnsclient,
		mDnsCache:        dnsCache,
		hmDnsCache:       hmDnsCache,
		hostsFileData:    hostsFileData,
		dialerHistory:    dialerHistory,
		dialerTLSData:    dialerTLSData,
		dialer:           dialer,
		proxyDialer:      options.ProxyDialer,
		options:          &options,
		networkpolicy:    np,
		searchDomains:    searchDomains,
		ndots:            ndots,
		dialCache:        gcache.New[string, *utils.DialWrap](MaxDialCacheSize).Build(),
		resolutionsGroup: &singleflight.Group{},
	}

	if options.MaxTemporaryErrors > 0 && options.MaxTemporaryToPermanentDuration > 0 {
		d.dialTimeoutErrors = gcache.New[string, *atomic.Uint32](MaxDialCacheSize).Expiration(options.MaxTemporaryToPermanentDuration).Build()
	}

	return d, nil
}

func createNetworkPolicy(options Options) (*networkpolicy.NetworkPolicy, error) {
	var npOptions networkpolicy.Options
	if options.WithNetworkPolicyOptions != nil {
		npOptions = *options.WithNetworkPolicyOptions
	}

	// Populate deny list if necessary
	npOptions.DenyList = append(npOptions.DenyList, options.Deny...)
	// Populate allow list if necessary
	npOptions.AllowList = append(npOptions.AllowList, options.Allow...)

	npOptions.AllowPortList = append(npOptions.AllowPortList, options.AllowPortList...)
	npOptions.DenyPortList = append(npOptions.DenyPortList, options.DenyPortList...)

	npOptions.AllowSchemeList = append(npOptions.AllowSchemeList, options.AllowSchemeList...)
	npOptions.DenySchemeList = append(npOptions.DenySchemeList, options.DenySchemeList...)

	np, err := networkpolicy.New(npOptions)
	return np, err
}

// Dial function compatible with net/http
func (d *Dialer) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        false,
		shouldUseZTLS:       false,
		tlsconfig:           nil,
		ztlsconfig:          nil,
		impersonateStrategy: impersonate.None,
		impersonateIdentity: nil,
	})
}

// DialTLS with encrypted connection, using Options.TLSConfig, or
// Options.ZTLSConfig when Options.WithZTLS is set.
//
// Note that the default configuration, used when those are nil, skips
// certificate verification and is not intended to be secure. Set
// Options.TLSConfig, or use the DialTLSWithConfig or
// DialTLSWithConfigImpersonate methods instead.
func (d *Dialer) DialTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if d.options.WithZTLS {
		return d.DialZTLSWithConfig(ctx, network, address, d.defaultZTLSConfig())
	}
	return d.DialTLSWithConfig(ctx, network, address, d.defaultTLSConfig())
}

// DialZTLS with encrypted connection using ztls and Options.ZTLSConfig
//
// Note that the default configuration, used when Options.ZTLSConfig is nil,
// is included for compatibility with the Go version <1.22, and is not
// intended to be secure. Set Options.ZTLSConfig, or use the
// DialZTLSWithConfig method instead.
func (d *Dialer) DialZTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	return d.DialZTLSWithConfig(ctx, network, address, d.defaultZTLSConfig())
}

func (d *Dialer) defaultTLSConfig() *tls.Config {
	if d.options.TLSConfig != nil {
		return d.options.TLSConfig
	}
	return DefaultTLSConfig
}

func (d *Dialer) defaultZTLSConfig() *ztls.Config {
	if d.options.ZTLSConfig != nil {
		return d.options.ZTLSConfig
	}
	return DefaultZTLSConfig
}

// DialTLS with encrypted connection
func (d *Dialer) DialTLSWithConfig(ctx context.Context, network, address string, config *tls.Config) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        true,
		shouldUseZTLS:       false,
		tlsconfig:           config,
		ztlsconfig:          nil,
		impersonateStrategy: impersonate.None,
		impersonateIdentity: nil,
	})
}

// DialTLSWithConfigImpersonate dials tls with impersonation
//
// The config applies as in DialTLSWithConfig, except that the impersonated
// ClientHello decides what it offers, such as cipher suites and curves. Only
// TLS 1.3 sessions are stored in config.ClientSessionCache, and they resume
// only when the ClientHello has a pre_shared_key extension. utls can't resume
// a session when the server asks for another key share, so that dial fails
// and drops the session.
//
// If config.NextProtos is set, it replaces the protocols in the ALPN extension
// of the impersonated ClientHello, which can change its JA4 fingerprint but not
// its JA3 one. A ClientHello without ALPN still sends none. If NextProtos is
// empty, the ClientHello keeps its own protocols.
//
// config.MinVersion and config.MaxVersion limit the version that the server
// may select, but the ClientHello still offers its own versions, so the dial
// fails when the server selects one outside them. A zero MinVersion or
// MaxVersion leaves that limit to the ClientHello.
func (d *Dialer) DialTLSWithConfigImpersonate(ctx context.Context, network, address string, config *tls.Config, impersonate impersonate.Strategy, identity *impersonate.Identity) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        true,
		shouldUseZTLS:       false,
		tlsconfig:           config,
		ztlsconfig:          nil,
		impersonateStrategy: impersonate,
		impersonateIdentity: identity,
	})
}

// DialZTLSWithConfig dials ztls with config
func (d *Dialer) DialZTLSWithConfig(ctx context.Context, network, address string, config *ztls.Config) (conn net.Conn, err error) {
	return d.dial(ctx, &dialOptions{
		network:             network,
		address:             address,
		shouldUseTLS:        false,
		shouldUseZTLS:       true,
		tlsconfig:           nil,
		ztlsconfig:          config,
		impersonateStrategy: impersonate.None,
		impersonateIdentity: nil,
	})
}

// Close instance and cleanups
func (d *Dialer) Close() {
	if d.mDnsCache != nil {
		d.mDnsCache.Purge()
	}
	if d.hmDnsCache != nil {
		_ = d.hmDnsCache.Close()
	}
	if d.options.WithDialerHistory && d.dialerHistory != nil {
		_ = d.dialerHistory.Close()
	}
	if d.options.WithTLSData {
		_ = d.dialerTLSData.Close()
	}
	if d.dialCache != nil {
		d.dialCache.Purge()
	}
	if d.dialTimeoutErrors != nil {
		d.dialTimeoutErrors.Purge()
	}
	// do not close hosts file as it is meant to be shared
}

// GetDialedIP returns the ip dialed by the HTTP client
func (d *Dialer) GetDialedIP(hostname string) string {
	if !d.options.WithDialerHistory || d.dialerHistory == nil {
		return ""
	}
	hostname = asAscii(hostname)
	v, ok := d.dialerHistory.Get(hostname)
	if ok {
		return string(v)
	}

	return ""
}

// GetTLSData returns the tls data for a hostname
func (d *Dialer) GetTLSData(hostname string) (*cryptoutil.TLSData, error) {
	hostname = asAscii(hostname)
	if !d.options.WithTLSData {
		return nil, NoTLSHistoryError
	}
	v, ok := d.dialerTLSData.Get(hostname)
	if !ok {
		return nil, NoTLSDataError
	}

	var tlsData cryptoutil.TLSData
	err := json.NewDecoder(bytes.NewReader(v)).Decode(&tlsData)
	if err != nil {
		return nil, err
	}

	return &tlsData, nil
}

// GetDNSDataFromCache cached by the resolver
func (d *Dialer) GetDNSDataFromCache(hostname string) (*retryabledns.DNSData, error) {
	hostname = asAscii(hostname)
	var data retryabledns.DNSData
	var dataBytes []byte
	var ok bool
	if d.hostsFileData != nil {
		dataBytes, ok = d.hostsFileData.Get(hostname)
	}
	if !ok {
		if d.mDnsCache != nil {
			return d.mDnsCache.GetIFPresent(hostname)
		}

		dataBytes, ok = d.hmDnsCache.Get(hostname)
		if !ok {
			return nil, NoDNSDataError
		}
	}
	err := data.Unmarshal(dataBytes)
	return &data, err
}

// GetDNSData for the given hostname
func (d *Dialer) GetDNSData(hostname string) (*retryabledns.DNSData, error) {
	hostname = asAscii(hostname)
	// support http://[::1] http://[::1]:8080
	// https://datatracker.ietf.org/doc/html/rfc2732
	// It defines a syntax
	// for IPv6 addresses and allows the use of "[" and "]" within a URI
	// explicitly for this reserved purpose.
	if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
		ipv6host := hostname[1:strings.LastIndex(hostname, "]")]
		if ip := net.ParseIP(ipv6host); ip != nil {
			if ip.To16() != nil {
				return &retryabledns.DNSData{AAAA: []string{ip.To16().String()}}, nil
			}
		}
	}
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.To4() != nil {
			return &retryabledns.DNSData{A: []string{hostname}}, nil
		}
		if ip.To16() != nil {
			return &retryabledns.DNSData{AAAA: []string{hostname}}, nil
		}
	}

	var (
		data *retryabledns.DNSData
		err  error
	)

	data, err = d.GetDNSDataFromCache(hostname)
	if err == nil {
		return data, nil
	}

	data, err = d.resolveWithSearch(hostname)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, ResolveHostError
	}

	// normalize host to original input for caching/telemetry consistency.
	data.Host = hostname

	if len(data.A)+len(data.AAAA) > 0 {
		if d.mDnsCache != nil {
			if setErr := d.mDnsCache.Set(hostname, data); setErr != nil {
				return nil, setErr
			}
		}

		if d.hmDnsCache != nil {
			b, errX := data.Marshal()
			if errX != nil {
				return nil, errX
			}

			if setErr := d.hmDnsCache.Set(hostname, b); setErr != nil {
				return nil, setErr
			}
		}
	}

	return data, nil
}

// resolveWithSearch replicates resolv.conf search + ndots behavior before hitting DNS.
func (d *Dialer) resolveWithSearch(hostname string) (*retryabledns.DNSData, error) {
	// absolute names or trailing dot skip search-domain expansion.
	if before, ok := strings.CutSuffix(hostname, "."); ok {
		trimmed := before
		return d.dnsclient.Resolve(trimmed)
	}

	dotCount := strings.Count(hostname, ".")
	var candidates []string

	seen := make(map[string]struct{})
	addCandidate := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}

		seen[name] = struct{}{}
		candidates = append(candidates, name)
	}

	if dotCount >= d.ndots {
		addCandidate(hostname)
	}

	for _, domain := range d.searchDomains {
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" {
			continue
		}

		candidate := hostname + "." + domain
		addCandidate(candidate)
	}

	// final absolute attempt.
	addCandidate(hostname)

	var lastErr error
	for _, name := range candidates {
		data, err := d.dnsclient.Resolve(name)
		if err != nil {
			lastErr = err
			continue
		}

		if data != nil && (len(data.A) > 0 || len(data.AAAA) > 0) {
			return data, nil
		}

		// if no A/AAAA but no error, keep trying other candidates.
	}

	if d.options.EnableFallback {
		data, err := d.dnsclient.ResolveWithSyscall(hostname)
		if err == nil {
			return data, nil
		}

		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, ResolveHostError
}

var MaxDialerTimeout = time.Minute
var MinDialerTimeout = time.Second

// GetTimeout returns the maximum timeout allowed for dialer
func (d *Dialer) GetTimeout() time.Duration {
	to := d.options.DialerTimeout
	if to <= 0 || to > MaxDialerTimeout {
		to = MaxDialerTimeout
	}
	if to < MinDialerTimeout {
		to = MinDialerTimeout
	}
	return to
}

func getHMAPDBType(options Options) hybrid.DBType {
	switch options.DiskDbType {
	case Pogreb:
		return hybrid.PogrebDB
	default:
		return hybrid.LevelDB
	}
}
