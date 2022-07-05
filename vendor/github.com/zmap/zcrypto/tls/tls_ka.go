// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"
	"math/big"
	"regexp"
	"strconv"

	jsonKeys "github.com/zmap/zcrypto/json"
)

// SignatureAndHash is a SigAndHash that implements json.Marshaler and
// json.Unmarshaler
type SignatureAndHash SigAndHash

type auxSignatureAndHash struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	HashAlgorithm      string `json:"hash_algorithm"`
}

// MarshalJSON implements the json.Marshaler interface
func (sh *SignatureAndHash) MarshalJSON() ([]byte, error) {
	aux := auxSignatureAndHash{
		SignatureAlgorithm: nameForSignature(sh.Signature),
		HashAlgorithm:      nameForHash(sh.Hash),
	}
	return json.Marshal(&aux)
}

var unknownAlgorithmRegex = regexp.MustCompile(`unknown\.(\d+)`)

// UnmarshalJSON implements the json.Unmarshaler interface
func (sh *SignatureAndHash) UnmarshalJSON(b []byte) error {
	aux := new(auxSignatureAndHash)
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	sh.Signature = signatureToName(aux.SignatureAlgorithm)
	sh.Hash = hashToName(aux.HashAlgorithm)
	return nil
}

func (ka *rsaKeyAgreement) RSAParams() *jsonKeys.RSAPublicKey {
	out := new(jsonKeys.RSAPublicKey)
	out.PublicKey = ka.publicKey
	return out
}

func (ka *ecdheKeyAgreement) ECDHParams() *jsonKeys.ECDHParams {
	out := new(jsonKeys.ECDHParams)
	out.TLSCurveID = jsonKeys.TLSCurveID(ka.curveID)
	out.ServerPublic = &jsonKeys.ECPoint{}
	if ka.x != nil {
		out.ServerPublic.X = new(big.Int)
		out.ServerPublic.X.Set(ka.x)
	}
	if ka.y != nil {
		out.ServerPublic.Y = new(big.Int)
		out.ServerPublic.Y.Set(ka.y)
	}
	if len(ka.serverPrivKey) > 0 {
		out.ServerPrivate = new(jsonKeys.ECDHPrivateParams)
		out.ServerPrivate.Length = len(ka.serverPrivKey)
		out.ServerPrivate.Value = make([]byte, len(ka.serverPrivKey))
		copy(out.ServerPrivate.Value, ka.serverPrivKey)
	}
	return out
}

func (ka *ecdheKeyAgreement) ClientECDHParams() *jsonKeys.ECDHParams {
	out := new(jsonKeys.ECDHParams)
	out.TLSCurveID = jsonKeys.TLSCurveID(ka.curveID)
	out.ClientPublic = &jsonKeys.ECPoint{}
	if ka.clientX != nil {
		out.ClientPublic.X = new(big.Int)
		out.ClientPublic.X.Set(ka.clientX)
	}
	if ka.clientY != nil {
		out.ClientPublic.Y = new(big.Int)
		out.ClientPublic.Y.Set(ka.clientY)
	}

	if len(ka.clientPrivKey) > 0 {
		out.ClientPrivate = new(jsonKeys.ECDHPrivateParams)
		out.ClientPrivate.Length = len(ka.clientPrivKey)
		out.ClientPrivate.Value = make([]byte, len(ka.clientPrivKey))
		copy(out.ClientPrivate.Value, ka.clientPrivKey)
	}
	return out
}

func (ka *dheKeyAgreement) DHParams() *jsonKeys.DHParams {
	out := new(jsonKeys.DHParams)
	if ka.p != nil {
		out.Prime = new(big.Int).Set(ka.p)
	}
	if ka.g != nil {
		out.Generator = new(big.Int).Set(ka.g)
	}
	if ka.yServer != nil {
		out.ServerPublic = new(big.Int).Set(ka.yServer)
		if ka.yOurs != nil && ka.xOurs != nil && ka.yServer.Cmp(ka.yOurs) == 0 {
			out.ServerPrivate = new(big.Int).Set(ka.xOurs)
		}
	}
	return out
}

func (ka *dheKeyAgreement) ClientDHParams() *jsonKeys.DHParams {
	out := new(jsonKeys.DHParams)
	if ka.p != nil {
		out.Prime = new(big.Int).Set(ka.p)
	}
	if ka.g != nil {
		out.Generator = new(big.Int).Set(ka.g)
	}
	if ka.yClient != nil {
		out.ClientPublic = new(big.Int).Set(ka.yClient)
		if ka.yOurs != nil && ka.xOurs != nil && ka.yClient.Cmp(ka.yOurs) == 0 {
			out.ClientPrivate = new(big.Int).Set(ka.xOurs)
		}
	}
	return out
}

// DigitalSignature represents a signature for a digitally-signed-struct in the
// TLS record protocol. It is dependent on the version of TLS in use. In TLS
// 1.2, the first two bytes of the signature specify the signature and hash
// algorithms. These are contained the TLSSignature.Raw field, but also parsed
// out into TLSSignature.SigHashExtension. In older versions of TLS, the
// signature and hash extension is not used, and so
// TLSSignature.SigHashExtension will be empty. The version string is stored in
// TLSSignature.TLSVersion.
type DigitalSignature struct {
	Raw              []byte            `json:"raw"`
	Type             string            `json:"type,omitempty"`
	Valid            bool              `json:"valid"`
	SigHashExtension *SignatureAndHash `json:"signature_and_hash_type,omitempty"`
	Version          TLSVersion        `json:"tls_version"`
}

func signatureTypeToName(sigType uint8) string {
	switch sigType {
	case signatureRSA:
		return "rsa"
	case signatureDSA:
		return "dsa"
	case signatureECDSA:
		return "ecdsa"
	default:
		break
	}
	return "unknown." + strconv.Itoa(int(sigType))
}

func (ka *signedKeyAgreement) Signature() *DigitalSignature {
	out := DigitalSignature{
		Raw:     ka.raw,
		Type:    signatureTypeToName(ka.sigType),
		Valid:   ka.valid,
		Version: TLSVersion(ka.version),
	}
	if ka.version >= VersionTLS12 {
		out.SigHashExtension = new(SignatureAndHash)
		*out.SigHashExtension = SignatureAndHash(ka.sh)
	}
	return &out
}
