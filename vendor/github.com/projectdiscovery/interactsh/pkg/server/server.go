package server

import (
	"strings"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/projectdiscovery/stringsutil"
)

// Interaction is an interaction received to the server.
type Interaction struct {
	// Protocol for interaction, can contains HTTP/DNS/SMTP,etc.
	Protocol string `json:"protocol"`
	// UniqueID is the uniqueID for the subdomain receiving the interaction.
	UniqueID string `json:"unique-id"`
	// FullId is the full path for the subdomain receiving the interaction.
	FullId string `json:"full-id"`
	// QType is the question type for the interaction
	QType string `json:"q-type,omitempty"`
	// RawRequest is the raw request received by the interactsh server.
	RawRequest string `json:"raw-request,omitempty"`
	// RawResponse is the raw response sent by the interactsh server.
	RawResponse string `json:"raw-response,omitempty"`
	// SMTPFrom is the mail form field
	SMTPFrom string `json:"smtp-from,omitempty"`
	// RemoteAddress is the remote address for interaction
	RemoteAddress string `json:"remote-address"`
	// Timestamp is the timestamp for the interaction
	Timestamp time.Time `json:"timestamp"`
}

// Options contains configuration options for the servers
type Options struct {
	// Domains is the list domains for the instance.
	Domains []string
	// IPAddress is the IP address of the current server.
	IPAddress string
	// ListenIP is the IP address to listen servers on
	ListenIP string
	// DomainPort is the port to listen DNS servers on
	DnsPort int
	// HttpPort is the port to listen HTTP server on
	HttpPort int
	// HttpsPort is the port to listen HTTPS server on
	HttpsPort int
	// SmbPort is the port to listen Smb server on
	SmbPort int
	// SmtpPort is the port to listen Smtp server on
	SmtpPort int
	// SmtpsPort is the port to listen Smtps server on
	SmtpsPort int
	// SmtpAutoTLSPort is the port to listen Smtp autoTLS server on
	SmtpAutoTLSPort int
	// FtpPort is the port to listen Ftp server on
	FtpPort int
	// FtpPort is the port to listen Ftp server on
	LdapPort int
	// Hostmaster is the hostmaster email for the server.
	Hostmasters []string
	// Storage is a storage for interaction data storage
	Storage storage.Storage
	// Auth requires client to authenticate
	Auth bool
	// HTTPIndex is the http index file for server
	HTTPIndex string
	// HTTPDirectory is the directory for interact server
	HTTPDirectory string
	// Token required to retrieve interactions
	Token string
	// Enable root tld interactions
	RootTLD bool
	// OriginURL for the HTTP Server
	OriginURL string
	// FTPDirectory or temporary one
	FTPDirectory string
	// ScanEverywhere for potential correlation id
	ScanEverywhere bool
	// CorrelationIdLength of preamble
	CorrelationIdLength int
	// CorrelationIdNonceLength of the unique identifier
	CorrelationIdNonceLength int
	// Certificate Path
	CertificatePath string
	// Private Key Path
	PrivateKeyPath string
	// CustomRecords is a file containing custom DNS records
	CustomRecords string
	// HTTP header containing origin IP
	OriginIPHeader string
	// Version is the version of interactsh server
	Version string
	// DiskStorage enables storing interactions on disk
	DiskStorage bool
	// DiskStoragePath defines the disk storage location
	DiskStoragePath string
	// DynamicResp enables dynamic HTTP response
	DynamicResp bool
	// EnableMetrics enables metrics endpoint
	EnableMetrics bool

	ACMEStore *acme.Provider
	Stats     *Metrics
}

func (options *Options) GetIdLength() int {
	return options.CorrelationIdLength + options.CorrelationIdNonceLength
}

// URLReflection returns a reversed part of the URL payload
// which is checked in the response.
func (options *Options) URLReflection(URL string) string {
	randomID := options.getURLIDComponent(URL)

	rns := []rune(randomID)
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}
	return string(rns)
}

// getURLIDComponent returns the interactsh ID
func (options *Options) getURLIDComponent(URL string) string {
	parts := strings.Split(URL, ".")

	var randomID string
	for _, part := range parts {
		for scanChunk := range stringsutil.SlideWithLength(part, options.GetIdLength()) {
			if options.isCorrelationID(scanChunk) {
				randomID = part
			}
		}
	}

	return randomID
}
