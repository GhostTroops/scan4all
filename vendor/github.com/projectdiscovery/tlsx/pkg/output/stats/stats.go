package stats

import "sync/atomic"

var (
	// cryptoTLSConnections contains number of connections made with
	// crypto/tls
	cryptoTLSConnections uint64
	// zCryptoTLSConnections contains number of connections made with
	// zcrypto/tls
	zcryptoTLSConnections uint64
	// opensslTLSConnections contains number of connections made with
	// openssl
	opensslTLSConnections uint64
)

// IncrementCryptoTLSConnections increments crypto/tls connections
func IncrementCryptoTLSConnections() {
	atomic.AddUint64(&cryptoTLSConnections, 1)
}

// IncrementZcryptoTLSConnections increments zcrypto/tls connections
func IncrementZcryptoTLSConnections() {
	atomic.AddUint64(&zcryptoTLSConnections, 1)
}

// IncrementOpensslTLSConnections increments openssl connections
func IncrementOpensslTLSConnections() {
	atomic.AddUint64(&opensslTLSConnections, 1)
}

// LoadCryptoTLSConnections returns crypto/tls connections
func LoadCryptoTLSConnections() uint64 {
	return atomic.LoadUint64(&cryptoTLSConnections)
}

// LoadZcryptoTLSConnections returns zcrypto/tls connections
func LoadZcryptoTLSConnections() uint64 {
	return atomic.LoadUint64(&zcryptoTLSConnections)
}

// LoadOpensslTLSConnections returns openssl connections
func LoadOpensslTLSConnections() uint64 {
	return atomic.LoadUint64(&opensslTLSConnections)
}
