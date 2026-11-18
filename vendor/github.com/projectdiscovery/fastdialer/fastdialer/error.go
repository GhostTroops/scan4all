package fastdialer

import "github.com/projectdiscovery/utils/errkit"

var (
	CouldNotConnectError  = errkit.New("could not connect to any address found for host").SetKind(errkit.ErrKindNetworkPermanent)
	NoAddressFoundError   = errkit.New("no address found for host").SetKind(errkit.ErrKindNetworkPermanent)
	NoAddressAllowedError = errkit.New("denied address found for host").SetKind(errkit.ErrKindNetworkPermanent)
	NoPortSpecifiedError  = errkit.New("port was not specified").SetKind(errkit.ErrKindNetworkPermanent)
	MalformedIP6Error     = errkit.New("malformed IPv6 address").SetKind(errkit.ErrKindNetworkPermanent)
	ResolveHostError      = errkit.New("could not resolve host").SetKind(errkit.ErrKindNetworkPermanent)
	NoTLSHistoryError     = errkit.New("no tls data history available")
	NoTLSDataError        = errkit.New("no tls data found for the key")
	NoDNSDataError        = errkit.New("no data found")
	AsciiConversionError  = errkit.New("could not convert hostname to ASCII")
	ErrDialTimeout        = errkit.New("dial timeout").SetKind(errkit.ErrKindNetworkTemporary)
)
