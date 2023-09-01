// Copyright 2021 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	circlPki "github.com/cloudflare/circl/pki"
	circlSign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium3"
)

// To add a signature scheme from Circl
//
//   1. make sure it implements TLSScheme and CertificateScheme,
//   2. follow the instructions in crypto/x509/x509_cf.go
//   3. add a signature<NameOfAlg> to the iota in common.go
//   4. add row in the circlSchemes lists below

var circlSchemes = [...]struct {
	sigType uint8
	scheme  circlSign.Scheme
}{
	{signatureEdDilithium3, eddilithium3.Scheme()},
}

func circlSchemeBySigType(sigType uint8) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.sigType == sigType {
			return cs.scheme
		}
	}
	return nil
}

func sigTypeByCirclScheme(scheme circlSign.Scheme) uint8 {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sigType
		}
	}
	return 0
}

var supportedSignatureAlgorithmsWithCircl []SignatureScheme

// supportedSignatureAlgorithms returns enabled signature schemes. PQ signature
// schemes are only included when tls.Config#PQSignatureSchemesEnabled is set
// and FIPS-only mode is not enabled.
func (c *Config) supportedSignatureAlgorithms() []SignatureScheme {
	// If FIPS-only mode is requested, do not add other algos.
	if needFIPS() {
		return supportedSignatureAlgorithms()
	}
	if c != nil && c.PQSignatureSchemesEnabled {
		return supportedSignatureAlgorithmsWithCircl
	}
	return defaultSupportedSignatureAlgorithms
}

func init() {
	supportedSignatureAlgorithmsWithCircl = append([]SignatureScheme{}, defaultSupportedSignatureAlgorithms...)
	for _, cs := range circlSchemes {
		supportedSignatureAlgorithmsWithCircl = append(supportedSignatureAlgorithmsWithCircl,
			SignatureScheme(cs.scheme.(circlPki.TLSScheme).TLSIdentifier()))
	}
}
