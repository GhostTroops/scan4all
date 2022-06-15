package retryabledns

import "time"

type Options struct {
	BaseResolvers []string
	MaxRetries    int
	Timeout       time.Duration
	Hostsfile     bool
}
