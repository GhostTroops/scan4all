package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/projectdiscovery/cryptoutil"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/networkpolicy"
	retryabledns "github.com/projectdiscovery/retryabledns"
	ztls "github.com/zmap/zcrypto/tls"
)

// Dialer structure containing data information
type Dialer struct {
	options       *Options
	dnsclient     *retryabledns.Client
	hm            *hybrid.HybridMap
	dialerHistory *hybrid.HybridMap
	dialerTLSData *hybrid.HybridMap
	dialer        *net.Dialer
	networkpolicy *networkpolicy.NetworkPolicy
}

// NewDialer instance
func NewDialer(options Options) (*Dialer, error) {
	var resolvers []string
	// Add system resolvers as the first to be tried
	if options.ResolversFile {
		systemResolvers, err := loadResolverFile()
		if err == nil && len(systemResolvers) > 0 {
			resolvers = systemResolvers
		}
	}

	cacheOptions := getHMapConfiguration(options)
	resolvers = append(resolvers, options.BaseResolvers...)
	hm, err := hybrid.New(cacheOptions)
	if err != nil {
		return nil, err
	}
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
			DualStack: true,
		}
	}

	// load hardcoded values from host file
	if options.HostsFile {
		// nolint:errcheck // if they cannot be loaded it's not a hard failure
		loadHostsFile(hm)
	}
	dnsclient := retryabledns.New(resolvers, options.MaxRetries)

	var npOptions networkpolicy.Options
	// Populate deny list if necessary
	npOptions.DenyList = append(npOptions.DenyList, options.Deny...)
	// Populate allow list if necessary
	npOptions.AllowList = append(npOptions.AllowList, options.Allow...)

	np, err := networkpolicy.New(npOptions)
	if err != nil {
		return nil, err
	}

	return &Dialer{dnsclient: dnsclient, hm: hm, dialerHistory: dialerHistory, dialerTLSData: dialerTLSData, dialer: dialer, options: &options, networkpolicy: np}, nil
}

// Dial function compatible with net/http
func (d *Dialer) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = d.dial(ctx, network, address, false, false, nil, nil)
	return
}

// DialTLS with encrypted connection
func (d *Dialer) DialTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if d.options.WithZTLS {
		return d.DialZTLSWithConfig(ctx, network, address, &ztls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	}

	return d.DialTLSWithConfig(ctx, network, address, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
}

// DialZTLS with encrypted connection using ztls
func (d *Dialer) DialZTLS(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = d.DialZTLSWithConfig(ctx, network, address, &ztls.Config{InsecureSkipVerify: true})
	return
}

// DialTLS with encrypted connection
func (d *Dialer) DialTLSWithConfig(ctx context.Context, network, address string, config *tls.Config) (conn net.Conn, err error) {
	conn, err = d.dial(ctx, network, address, true, false, config, nil)
	return
}

func (d *Dialer) DialZTLSWithConfig(ctx context.Context, network, address string, config *ztls.Config) (conn net.Conn, err error) {
	// ztls doesn't support tls13
	if IsTLS13(config) {
		stdTLSConfig, err := AsTLSConfig(config)
		if err != nil {
			return nil, err
		}
		return d.dial(ctx, network, address, true, false, stdTLSConfig, nil)
	}
	return d.dial(ctx, network, address, false, true, nil, config)
}

func (d *Dialer) dial(ctx context.Context, network, address string, shouldUseTLS, shouldUseZTLS bool, tlsconfig *tls.Config, ztlsconfig *ztls.Config) (conn net.Conn, err error) {
	var hostname, port, fixedIP string

	if strings.HasPrefix(address, "[") {
		closeBracketIndex := strings.Index(address, "]")
		if closeBracketIndex == -1 {
			return nil, MalformedIP6Error
		}
		hostname = address[:closeBracketIndex+1]
		if len(address) < closeBracketIndex+2 {
			return nil, NoPortSpecifiedError
		}
		port = address[closeBracketIndex+2:]
	} else {
		addressParts := strings.SplitN(address, ":", 3)
		numberOfParts := len(addressParts)

		if numberOfParts >= 2 {
			// ip|host:port
			hostname = addressParts[0]
			port = addressParts[1]
			// ip|host:port:ip => curl --resolve ip:port:ip
			if numberOfParts > 2 {
				fixedIP = addressParts[2]
			}
			// check if the ip is within the context
			if ctxIP := ctx.Value("ip"); ctxIP != nil {
				fixedIP = fmt.Sprint(ctxIP)
			}
		} else {
			// no port => error
			return nil, NoPortSpecifiedError
		}
	}

	// check if data is in cache
	hostname = asAscii(hostname)
	data, err := d.GetDNSData(hostname)
	if err != nil {
		// otherwise attempt to retrieve it
		data, err = d.dnsclient.Resolve(hostname)

	}
	if data == nil {
		return nil, ResolveHostError
	}

	if err != nil || len(data.A)+len(data.AAAA) == 0 {
		return nil, NoAddressFoundError
	}

	var numInvalidIPS int
	var IPS []string
	// use fixed ip as first
	if fixedIP != "" {
		IPS = append(IPS, fixedIP)
	}
	IPS = append(IPS, append(data.A, data.AAAA...)...)

	// Dial to the IPs finally.
	for _, ip := range IPS {
		// check if we have allow/deny list
		if !d.networkpolicy.Validate(ip) {
			numInvalidIPS++
			continue
		}
		hostPort := net.JoinHostPort(ip, port)
		if shouldUseTLS {
			tlsconfigCopy := tlsconfig.Clone()
			switch {
			case d.options.SNIName != "":
				tlsconfigCopy.ServerName = d.options.SNIName
			case ctx.Value(SniName) != nil:
				sniName := ctx.Value(SniName).(string)
				tlsconfigCopy.ServerName = sniName
			case !iputil.IsIP(hostname):
				tlsconfigCopy.ServerName = hostname
			}
			conn, err = tls.DialWithDialer(d.dialer, network, hostPort, tlsconfigCopy)
		} else if shouldUseZTLS {
			ztlsconfigCopy := ztlsconfig.Clone()
			switch {
			case d.options.SNIName != "":
				ztlsconfigCopy.ServerName = d.options.SNIName
			case ctx.Value(SniName) != nil:
				sniName := ctx.Value(SniName).(string)
				ztlsconfigCopy.ServerName = sniName
			case !iputil.IsIP(hostname):
				ztlsconfigCopy.ServerName = hostname
			}
			conn, err = ztls.DialWithDialer(d.dialer, network, hostPort, ztlsconfigCopy)
		} else {
			conn, err = d.dialer.DialContext(ctx, network, hostPort)
		}
		if err == nil {
			if d.options.WithDialerHistory && d.dialerHistory != nil {
				setErr := d.dialerHistory.Set(hostname, []byte(ip))
				if setErr != nil {
					return nil, setErr
				}
			}
			if d.options.WithTLSData && shouldUseTLS {
				if connTLS, ok := conn.(*tls.Conn); ok {
					var data bytes.Buffer
					connState := connTLS.ConnectionState()
					err := json.NewEncoder(&data).Encode(cryptoutil.TLSGrab(&connState))
					if err != nil {
						return nil, err
					}
					setErr := d.dialerTLSData.Set(hostname, data.Bytes())
					if setErr != nil {
						return nil, setErr
					}
				}
			}
			break
		}
	}

	if conn == nil {
		if numInvalidIPS == len(IPS) {
			return nil, NoAddressAllowedError
		}
		return nil, CouldNotConnectError
	}

	if err != nil {
		return nil, err
	}

	return
}

// Close instance and cleanups
func (d *Dialer) Close() {
	if d.hm != nil {
		d.hm.Close()
	}
	if d.options.WithDialerHistory && d.dialerHistory != nil {
		d.dialerHistory.Close()
	}
	if d.options.WithTLSData {
		d.dialerTLSData.Close()
	}
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
	dataBytes, ok := d.hm.Get(hostname)
	if !ok {
		return nil, NoDNSDataError
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
	if err != nil {
		data, err = d.dnsclient.Resolve(hostname)
		if err != nil && d.options.EnableFallback {
			data, err = d.dnsclient.ResolveWithSyscall(hostname)
		}
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, ResolveHostError
		}
		b, _ := data.Marshal()
		err = d.hm.Set(hostname, b)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return data, nil
}

func getHMapConfiguration(options Options) hybrid.Options {
	var cacheOptions hybrid.Options
	switch options.CacheType {
	case Memory:
		cacheOptions = hybrid.DefaultMemoryOptions
		if options.CacheMemoryMaxItems > 0 {
			cacheOptions.MaxMemorySize = options.CacheMemoryMaxItems
		}
	case Disk:
		cacheOptions = hybrid.DefaultDiskOptions
		cacheOptions.DBType = getHMAPDBType(options)
	case Hybrid:
		cacheOptions = hybrid.DefaultHybridOptions
	}
	if options.WithCleanup {
		cacheOptions.Cleanup = options.WithCleanup
		if options.CacheMemoryMaxItems > 0 {
			cacheOptions.MaxMemorySize = options.CacheMemoryMaxItems
		}
		cacheOptions.DBType = getHMAPDBType(options)
	}
	return cacheOptions
}

func getHMAPDBType(options Options) hybrid.DBType {
	switch options.DiskDbType {
	case Pogreb:
		return hybrid.PogrebDB
	default:
		return hybrid.LevelDB
	}
}
