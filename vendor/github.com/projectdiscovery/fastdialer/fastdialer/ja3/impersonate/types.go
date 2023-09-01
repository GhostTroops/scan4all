package impersonate

import (
	utls "github.com/refraction-networking/utls"
)

// Strategy is the type of strategy to use for impersonation
type Strategy uint8

const (
	// None is the default strategy which use the default client hello spec
	None Strategy = iota
	// Random is the strategy which use a random client hello spec
	Random
	// JA3 or Raw is the strategy which parses a client hello spec from ja3 full string
	Custom
)

// Identity contains the structured client hello spec
type Identity utls.ClientHelloSpec
