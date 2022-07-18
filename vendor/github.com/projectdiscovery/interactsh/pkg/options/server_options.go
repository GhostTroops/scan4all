package options

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

type CLIServerOptions struct {
	Config                   string
	Version                  bool
	Debug                    bool
	Domains                  goflags.CommaSeparatedStringSlice
	DnsPort                  int
	IPAddress                string
	ListenIP                 string
	HttpPort                 int
	HttpsPort                int
	Hostmasters              []string
	LdapWithFullLogger       bool
	Eviction                 int
	Responder                bool
	Smb                      bool
	SmbPort                  int
	SmtpPort                 int
	SmtpsPort                int
	SmtpAutoTLSPort          int
	FtpPort                  int
	LdapPort                 int
	Ftp                      bool
	Auth                     bool
	Token                    string
	OriginURL                string
	RootTLD                  bool
	FTPDirectory             string
	SkipAcme                 bool
	CorrelationIdLength      int
	CorrelationIdNonceLength int
	ScanEverywhere           bool
	CertificatePath          string
	PrivateKeyPath           string
	OriginIPHeader           string
}

func (cliServerOptions *CLIServerOptions) AsServerOptions() *server.Options {
	return &server.Options{
		Domains:                  cliServerOptions.Domains,
		DnsPort:                  cliServerOptions.DnsPort,
		IPAddress:                cliServerOptions.IPAddress,
		ListenIP:                 cliServerOptions.ListenIP,
		HttpPort:                 cliServerOptions.HttpPort,
		HttpsPort:                cliServerOptions.HttpsPort,
		Hostmasters:              cliServerOptions.Hostmasters,
		SmbPort:                  cliServerOptions.SmbPort,
		SmtpPort:                 cliServerOptions.SmtpPort,
		SmtpsPort:                cliServerOptions.SmtpsPort,
		SmtpAutoTLSPort:          cliServerOptions.SmtpAutoTLSPort,
		FtpPort:                  cliServerOptions.FtpPort,
		LdapPort:                 cliServerOptions.LdapPort,
		Auth:                     cliServerOptions.Auth,
		Token:                    cliServerOptions.Token,
		OriginURL:                cliServerOptions.OriginURL,
		RootTLD:                  cliServerOptions.RootTLD,
		FTPDirectory:             cliServerOptions.FTPDirectory,
		CorrelationIdLength:      cliServerOptions.CorrelationIdLength,
		CorrelationIdNonceLength: cliServerOptions.CorrelationIdNonceLength,
		ScanEverywhere:           cliServerOptions.ScanEverywhere,
		CertificatePath:          cliServerOptions.CertificatePath,
		PrivateKeyPath:           cliServerOptions.PrivateKeyPath,
		OriginIPHeader:           cliServerOptions.OriginIPHeader,
	}
}
