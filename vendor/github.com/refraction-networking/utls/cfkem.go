// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.
//
// Glue to add Circl's (post-quantum) hybrid KEMs.
//
// To enable set CurvePreferences with the desired scheme as the first element:
//
//   import (
//      "crypto/tls"
//
//          [...]
//
//   config.CurvePreferences = []tls.CurveID{
//      tls.X25519Kyber768Draft00,
//      tls.X25519,
//      tls.P256,
//   }

package tls

import (
	"fmt"
	"io"

	"crypto/ecdh"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
)

// Either *ecdh.PrivateKey or *kemPrivateKey
type clientKeySharePrivate interface{}

type kemPrivateKey struct {
	secretKey kem.PrivateKey
	curveID   CurveID
}

var (
	X25519Kyber512Draft00    = CurveID(0xfe30)
	X25519Kyber768Draft00    = CurveID(0x6399)
	X25519Kyber768Draft00Old = CurveID(0xfe31)
	P256Kyber768Draft00      = CurveID(0xfe32)
	invalidCurveID           = CurveID(0)
)

// Extract CurveID from clientKeySharePrivate
func clientKeySharePrivateCurveID(ks clientKeySharePrivate) CurveID {
	switch v := ks.(type) {
	case *kemPrivateKey:
		return v.curveID
	case *ecdh.PrivateKey:
		ret, ok := curveIDForCurve(v.Curve())
		if !ok {
			panic("cfkem: internal error: unknown curve")
		}
		return ret
	default:
		panic("cfkem: internal error: unknown clientKeySharePrivate")
	}
}

// Returns scheme by CurveID if supported by Circl
func curveIdToCirclScheme(id CurveID) kem.Scheme {
	switch id {
	case X25519Kyber512Draft00:
		return hybrid.Kyber512X25519()
	case X25519Kyber768Draft00, X25519Kyber768Draft00Old:
		return hybrid.Kyber768X25519()
	case P256Kyber768Draft00:
		return hybrid.P256Kyber768Draft00()
	}
	return nil
}

// Generate a new shared secret and encapsulates it for the packed
// public key in ppk using randomness from rnd.
func encapsulateForKem(scheme kem.Scheme, rnd io.Reader, ppk []byte) (
	ct, ss []byte, alert alert, err error) {
	pk, err := scheme.UnmarshalBinaryPublicKey(ppk)
	if err != nil {
		return nil, nil, alertIllegalParameter, fmt.Errorf("unpack pk: %w", err)
	}
	seed := make([]byte, scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, alertInternalError, fmt.Errorf("random: %w", err)
	}
	ct, ss, err = scheme.EncapsulateDeterministically(pk, seed)
	return ct, ss, alertIllegalParameter, err
}

// Generate a new keypair using randomness from rnd.
func generateKemKeyPair(scheme kem.Scheme, curveID CurveID, rnd io.Reader) (
	kem.PublicKey, *kemPrivateKey, error) {
	seed := make([]byte, scheme.SeedSize())
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, err
	}
	pk, sk := scheme.DeriveKeyPair(seed)
	return pk, &kemPrivateKey{sk, curveID}, nil
}
