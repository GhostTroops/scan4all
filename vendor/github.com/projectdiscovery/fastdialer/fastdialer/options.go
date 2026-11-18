package fastdialer

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/projectdiscovery/networkpolicy"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/proxy"
)

// DefaultResolvers trusted
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

type CacheType uint8

const (
	Memory CacheType = iota
	Disk
	Hybrid
)

type DiskDBType uint8

const (
	LevelDB DiskDBType = iota
	Pogreb
)

type Options struct {
	BaseResolvers            []string
	MaxRetries               int
	HostsFile                bool
	ResolversFile            bool
	EnableFallback           bool
	Allow                    []string
	Deny                     []string
	// Deprecated: has no effect, the dialer validates hosts and IPs, not URLs.
	AllowSchemeList          []string
	// Deprecated: has no effect, the dialer validates hosts and IPs, not URLs.
	DenySchemeList           []string
	AllowPortList            []int
	DenyPortList             []int
	CacheType                CacheType
	CacheMemoryMaxItems      int // used by Memory cache type
	DiskDbType               DiskDBType
	WithDialerHistory        bool
	WithCleanup              bool
	WithTLSData              bool
	DialerTimeout            time.Duration
	DialerKeepAlive          time.Duration
	Dialer                   *net.Dialer
	ProxyDialer              *proxy.Dialer
	WithZTLS                 bool
	SNIName                  string
	OnBeforeDial             func(hostname, IP, port string)
	// OnValidateTarget is called after network policy validation and before dialing.
	// If it returns an error, the target is considered invalid.
	OnValidateTarget         func(hostname, IP, port string) error
	OnInvalidTarget          func(hostname, IP, port string)
	OnDialCallback           func(hostname, IP string)
	DisableZtlsFallback      bool
	WithNetworkPolicyOptions *networkpolicy.Options
	// optional network policy override for sharing
	NetworkPolicy *networkpolicy.NetworkPolicy
	// optional logger to log errors(like hostfile init error)
	Logger *log.Logger
	// optional max temporary errors to mark as permanent
	MaxTemporaryErrors              int
	MaxTemporaryToPermanentDuration time.Duration

	// ConnectionCacheExpiry is the duration after which a cached connection
	// expires.
	//
	// Default is [DefaultConnExpiry].
	ConnectionCacheExpiry time.Duration

	// MaxResolverEntries limits the number of resolvers read from the resolvers
	// file.
	//
	// Default is [DefaultMaxResolverEntries].
	// Use -1 for unlimited entries.
	MaxResolverEntries int

	// Ndots enforces the resolv.conf(5) ndots: threshold for treating a name
	// as absolute before search domains are appended (see
	// https://man7.org/linux/man-pages/man5/resolv.conf.5.html).
	//
	// Default is [DefaultNdots].
	Ndots int

	// OnDialResult is called after each connection attempt with the caller's
	// context and the error, nil on success. Targets that fail before a
	// connection is attempted (resolution, policy) are not reported.
	OnDialResult func(ctx context.Context, hostname, port string, err error)

	// TLSConfig is the config of DialTLS. Default is [DefaultTLSConfig].
	// Configs passed to the WithConfig dial methods are used as given.
	TLSConfig *tls.Config
	// ZTLSConfig is the config of DialZTLS, and of DialTLS when WithZTLS is
	// set. Default is [DefaultZTLSConfig].
	ZTLSConfig *ztls.Config
}

// DefaultOptions of the cache
var DefaultOptions = Options{
	BaseResolvers:                   DefaultResolvers,
	MaxRetries:                      5,
	HostsFile:                       true,
	ResolversFile:                   true,
	CacheType:                       Memory,
	DialerTimeout:                   10 * time.Second,
	DialerKeepAlive:                 10 * time.Second,
	MaxTemporaryErrors:              30,
	MaxTemporaryToPermanentDuration: time.Minute,
}
