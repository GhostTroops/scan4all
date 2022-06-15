package rawhttp

import (
	"time"

	"github.com/projectdiscovery/rawhttp/clientpipeline"
)

// PipelineOptions contains options for pipelined http client
type PipelineOptions struct {
	Dialer              clientpipeline.DialFunc
	Host                string
	Timeout             time.Duration
	MaxConnections      int
	MaxPendingRequests  int
	AutomaticHostHeader bool
}

// DefaultPipelineOptions is the default options for pipelined http client
var DefaultPipelineOptions = PipelineOptions{
	Timeout:             30 * time.Second,
	MaxConnections:      5,
	MaxPendingRequests:  100,
	AutomaticHostHeader: true,
}
