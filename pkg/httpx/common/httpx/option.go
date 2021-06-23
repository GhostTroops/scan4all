package httpx

import (
	"time"
)

// Options contains configuration options for the client
type Options struct {
	RandomAgent      bool
	DefaultUserAgent string
	RequestOverride  RequestOverride
	HTTPProxy        string
	SocksProxy       string
	Threads          int
	CdnCheck         bool
	// Timeout is the maximum time to wait for the request
	Timeout time.Duration
	// RetryMax is the maximum number of retries
	RetryMax      int
	CustomHeaders map[string]string
	// VHostSimilarityRatio 1 - 100
	VHostSimilarityRatio int
	FollowRedirects      bool
	FollowHostRedirects  bool
	Unsafe               bool
	TLSGrab              bool
	// VHOSTs options
	VHostIgnoreStatusCode    bool
	VHostIgnoreContentLength bool
	VHostIgnoreNumberOfWords bool
	VHostIgnoreNumberOfLines bool
	VHostStripHTML           bool
	Allow                    []string
	Deny                     []string
}

// DefaultOptions contains the default options
var DefaultOptions = Options{
	RandomAgent: true,
	Threads:     25,
	Timeout:     30 * time.Second,
	RetryMax:    5,
	Unsafe:      false,
	CdnCheck:    true,
	// VHOSTs options
	VHostIgnoreStatusCode:    false,
	VHostIgnoreContentLength: true,
	VHostIgnoreNumberOfWords: false,
	VHostIgnoreNumberOfLines: false,
	VHostStripHTML:           false,
	VHostSimilarityRatio:     85,
	DefaultUserAgent:         "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
}
