package weblogic

import (
	"net/http"
	"sync"
)

var (
	transportMu       sync.RWMutex
	injectedTransport http.RoundTripper
)

// SetTransport installs a shared RoundTripper (the capture recorder) for the
// HTTP-based WebLogic checks. T3/IIOP use raw sockets and are unaffected.
// Passing nil restores the package's own transports.
func SetTransport(rt http.RoundTripper) {
	transportMu.Lock()
	injectedTransport = rt
	transportMu.Unlock()
}

func pickTransport(base http.RoundTripper) http.RoundTripper {
	transportMu.RLock()
	defer transportMu.RUnlock()
	if injectedTransport != nil {
		return injectedTransport
	}
	return base
}
