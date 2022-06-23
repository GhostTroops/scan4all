package fastdialer

import (
	"github.com/pkg/errors"
)

var (
	CouldNotConnectError  = errors.New("could not connect to any address found for host")
	NoAddressFoundError   = errors.New("no address found for host")
	NoAddressAllowedError = errors.New("denied address found for host")
	NoPortSpecifiedError  = errors.New("port was not specified")
	MalformedIP6Error     = errors.New("malformed IPv6 address")
	ResolveHostError      = errors.New("could not resolve host")
	NoTLSHistoryError     = errors.New("no tls data history available")
	NoTLSDataError        = errors.New("no tls data found for the key")
	NoDNSDataError        = errors.New("no data found")
	AsciiConversionError  = errors.New("could not convert hostname to ASCII")
)
