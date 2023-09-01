package doh

import (
	"fmt"
	"net/http"
	"time"
)

var DefaultTimeout = 5 * time.Second

type Options struct {
	DefaultResolver Resolver
	HttpClient      *http.Client
}

type Resolver struct {
	Name string
	URL  string
}

var (
	Cloudflare = Resolver{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query"}
	Google     = Resolver{Name: "Google", URL: "https://dns.google.com/resolve"}
	Quad9      = Resolver{Name: "Cloudflare", URL: "https://dns.quad9.net:5053/dns-query"}
	PowerDNS   = Resolver{Name: "PowerDNS", URL: "https://doh.powerdns.org/dns-query"}
	OpenDNS    = Resolver{Name: "OpenDNS", URL: "https://doh.opendns.com/dns-query"}
)

type QuestionType string

func (q QuestionType) ToString() string {
	return fmt.Sprint(q)
}

const (
	A     QuestionType = "A"
	AAAA  QuestionType = "AAAA"
	MX    QuestionType = "MX"
	NS    QuestionType = "NS"
	SOA   QuestionType = "SOA"
	PTR   QuestionType = "PTR"
	ANY   QuestionType = "ANY"
	CNAME QuestionType = "CNAME"
)

type Response struct {
	Status   int        `json:"Status"`
	TC       bool       `json:"TC"`
	RD       bool       `json:"RD"`
	RA       bool       `json:"RA"`
	AD       bool       `json:"AD"`
	CD       bool       `json:"CD"`
	Question []Question `json:"Question"`
	Answer   []Answer   `json:"Answer"`
	Comment  string
}

type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}
type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type Method string

const (
	MethodGet  Method = http.MethodGet
	MethodPost Method = http.MethodPost
)
