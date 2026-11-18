package tls

import (
	"crypto/ecdh"
)

// This file contains all the alias functions, symbols, names, etc. that
// was once used in the old version of the library.  This is to ensure
// backwards compatibility with the old version of the library.

// TLS Extensions

// UtlsExtendedMasterSecretExtension is an alias for ExtendedMasterSecretExtension.
//
// Deprecated: Use ExtendedMasterSecretExtension instead.
type UtlsExtendedMasterSecretExtension = ExtendedMasterSecretExtension

// Deprecated: Use KeySharePrivateKeys instead. This type is not used and will be removed in the future.
// KeySharesParameters serves as a in-memory storage for generated keypairs by UTLS when generating
// ClientHello. It is used to store both ecdhe and kem keypairs.
type KeySharesParameters struct{}

func NewKeySharesParameters() *KeySharesParameters { return &KeySharesParameters{} }

func (*KeySharesParameters) AddEcdheKeypair(curveID CurveID, ecdheKey *ecdh.PrivateKey, ecdhePubKey *ecdh.PublicKey) {
	return
}

func (*KeySharesParameters) GetEcdheKey(curveID CurveID) (ecdheKey *ecdh.PrivateKey, ok bool) { return }

func (*KeySharesParameters) GetEcdhePubkey(curveID CurveID) (params *ecdh.PublicKey, ok bool) { return }

func (*KeySharesParameters) AddKemKeypair(curveID CurveID, kemKey any, kemPubKey any) {
	return
}

func (ksp *KeySharesParameters) GetKemKey(curveID CurveID) (kemKey any, ok bool) { return }

func (ksp *KeySharesParameters) GetKemPubkey(curveID CurveID) (params any, ok bool) { return }
