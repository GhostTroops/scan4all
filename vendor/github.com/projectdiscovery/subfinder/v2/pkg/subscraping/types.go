package subscraping

import (
	"context"
	"net/http"
	"regexp"

	"go.uber.org/ratelimit"
)

// BasicAuth request's Authorization header
type BasicAuth struct {
	Username string
	Password string
}

// Source is an interface inherited by each passive source
type Source interface {
	// Run takes a domain as argument and a session object
	// which contains the extractor for subdomains, http client
	// and other stuff.
	Run(context.Context, string, *Session) <-chan Result
	// Name returns the name of the source
	Name() string
}

// Session is the option passed to the source, an option is created
// uniquely for each source.
type Session struct {
	// Extractor is the regex for subdomains created for each domain
	Extractor *regexp.Regexp
	// Keys is the API keys for the application
	Keys *Keys
	// Client is the current http client
	Client *http.Client
	// Rate limit instance
	RateLimiter ratelimit.Limiter
}

// Keys contains the current API Keys we have in store
type Keys struct {
	Binaryedge           string   `json:"binaryedge"`
	Bufferover           string   `json:"bufferover"`
	C99                  string   `json:"c99"`
	CensysToken          string   `json:"censysUsername"`
	CensysSecret         string   `json:"censysPassword"`
	Certspotter          string   `json:"certspotter"`
	Chaos                string   `json:"chaos"`
	Chinaz               string   `json:"chinaz"`
	DNSDB                string   `json:"dnsdb"`
	FofaUsername         string   `json:"fofa_username"`
	FofaSecret           string   `json:"fofa_secret"`
	FullHunt             string   `json:"fullhunt"`
	GitHub               []string `json:"github"`
	IntelXHost           string   `json:"intelXHost"`
	IntelXKey            string   `json:"intelXKey"`
	PassiveTotalUsername string   `json:"passivetotal_username"`
	PassiveTotalPassword string   `json:"passivetotal_password"`
	Robtex               string   `json:"robtex"`
	Securitytrails       string   `json:"securitytrails"`
	Shodan               string   `json:"shodan"`
	ThreatBook           string   `json:"threatbook"`
	URLScan              string   `json:"urlscan"`
	Virustotal           string   `json:"virustotal"`
	WhoisXMLAPI          string   `json:"whoisxmlapi"`
	ZoomEyeUsername      string   `json:"zoomeye_username"`
	ZoomEyePassword      string   `json:"zoomeye_password"`
	ZoomEyeKey           string   `json:"zoomeye_key"`
}

// Result is a result structure returned by a source
type Result struct {
	Type   ResultType
	Source string
	Value  string
	Error  error
}

// ResultType is the type of result returned by the source
type ResultType int

// Types of results returned by the source
const (
	Subdomain ResultType = iota
	Error
)
