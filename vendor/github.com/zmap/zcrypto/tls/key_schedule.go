// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"errors"
	"hash"
	"io"
	"math/big"
	"slices"

	jsonKeys "github.com/zmap/zcrypto/json"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

const (
	// https://github.com/golang/go/blob/1768cb40b838a36f9bdcbe5381f2e086483f22f5/src/crypto/tls/key_schedule.go#L97
	x25519ShareSize    = 32
	secP256r1ShareSize = 65
	secP384r1ShareSize = 97

	mlkem768EKSize  = mlkem.EncapsulationKeySize768  // 1184
	mlkem768CTSize  = mlkem.CiphertextSize768        // 1088
	mlkem1024EKSize = mlkem.EncapsulationKeySize1024 // 1568
	mlkem1024CTSize = mlkem.CiphertextSize1024       // 1568
	mlkemSSSize     = 32                             // ML-KEM shared secret size
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

// extract implements HKDF-Extract with the cipher suite hash.
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := c.deriveSecret(masterSecret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := c.deriveSecret(expMasterSecret, label, nil)
		h := c.hash.New()
		h.Write(context)
		return c.expandLabel(secret, "exporter", h.Sum(nil), length), nil
	}
}

// ecdheParameters implements Diffie-Hellman with either NIST curves or X25519,
// according to RFC 8446, Section 4.2.8.2.
type ecdheParameters interface {
	CurveID() CurveID
	PublicKey() []byte
	SharedKey(peerPublicKey []byte) []byte

	Clone() ecdheParameters
	MakeLog() (*jsonKeys.ECPoint, *jsonKeys.ECDHPrivateParams)
}

type tls13KeyShare interface {
	Group() CurveID
	PublicKey() []byte
	SharedKey(serverShare []byte) ([]byte, error)
}

func generateECDHEParameters(rand io.Reader, curveID CurveID) (ecdheParameters, error) {
	if curveID == X25519 {
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		return &x25519Parameters{privateKey: privateKey, publicKey: publicKey}, nil
	}

	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	p := &nistParameters{curveID: curveID}
	var err error
	p.privateKey, p.x, p.y, err = elliptic.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

type nistParameters struct {
	privateKey []byte
	x, y       *big.Int // public key
	curveID    CurveID
}

func (p *nistParameters) CurveID() CurveID {
	return p.curveID
}

func (p *nistParameters) PublicKey() []byte {
	curve, _ := curveForCurveID(p.curveID)
	return elliptic.Marshal(curve, p.x, p.y)
}

func (p *nistParameters) SharedKey(peerPublicKey []byte) []byte {
	curve, _ := curveForCurveID(p.curveID)
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}

	xShared, _ := curve.ScalarMult(x, y, p.privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)/8)
	return xShared.FillBytes(sharedKey)
}

func (p *nistParameters) Clone() ecdheParameters {
	clone := *p

	if p.privateKey != nil {
		clone.privateKey = make([]byte, len(p.privateKey))
		copy(clone.privateKey, p.privateKey)
	}

	if p.x != nil {
		clone.x = new(big.Int).Set(p.x)
	}

	if p.y != nil {
		clone.y = new(big.Int).Set(p.y)
	}

	return &clone
}

func (p *nistParameters) MakeLog() (*jsonKeys.ECPoint, *jsonKeys.ECDHPrivateParams) {
	public := new(jsonKeys.ECPoint)

	if p.x != nil {
		public.X = new(big.Int)
		public.X.Set(p.x)
	}

	if p.y != nil {
		public.Y = new(big.Int)
		public.Y.Set(p.y)
	}

	var private *jsonKeys.ECDHPrivateParams
	if len(p.privateKey) > 0 {
		private = new(jsonKeys.ECDHPrivateParams)
		private.Length = len(p.privateKey)
		private.Value = make([]byte, len(p.privateKey))
		copy(private.Value, p.privateKey)
	}

	return public, private
}

type x25519Parameters struct {
	privateKey []byte
	publicKey  []byte
}

func (p *x25519Parameters) CurveID() CurveID {
	return X25519
}

func (p *x25519Parameters) PublicKey() []byte {
	return p.publicKey[:]
}

func (p *x25519Parameters) SharedKey(peerPublicKey []byte) []byte {
	sharedKey, err := curve25519.X25519(p.privateKey, peerPublicKey)
	if err != nil {
		return nil
	}
	return sharedKey
}

func (p *x25519Parameters) Clone() ecdheParameters {
	clone := *p

	if p.privateKey != nil {
		clone.privateKey = make([]byte, len(p.privateKey))
		copy(clone.privateKey, p.privateKey)
	}

	if p.publicKey != nil {
		clone.publicKey = make([]byte, len(p.publicKey))
		copy(clone.publicKey, p.publicKey)
	}

	return &clone
}

func (p *x25519Parameters) MakeLog() (*jsonKeys.ECPoint, *jsonKeys.ECDHPrivateParams) {
	public := new(jsonKeys.ECPoint)

	if p.publicKey != nil {
		public.X = new(big.Int)
		public.X.SetBytes(p.publicKey)
	}

	var private *jsonKeys.ECDHPrivateParams
	if len(p.privateKey) > 0 {
		private = new(jsonKeys.ECDHPrivateParams)
		private.Length = len(p.privateKey)
		private.Value = make([]byte, len(p.privateKey))
		copy(private.Value, p.privateKey)
	}

	return public, private
}

func splitKeyShare(data []byte, firstHalfSize int, secondHalfSize int) ([]byte, []byte) {
	if len(data) != firstHalfSize+secondHalfSize {
		return nil, nil
	}
	return data[:firstHalfSize], data[firstHalfSize:]
}

type tls13ECDHEKeyShare struct {
	group  CurveID
	params ecdheParameters
}

func (k *tls13ECDHEKeyShare) Group() CurveID    { return k.group }
func (k *tls13ECDHEKeyShare) PublicKey() []byte { return k.params.PublicKey() }

func (k *tls13ECDHEKeyShare) SharedKey(serverShare []byte) ([]byte, error) {
	sk := k.params.SharedKey(serverShare)
	if sk == nil {
		return nil, errors.New("tls: invalid server key share")
	}
	return sk, nil
}

type tls13X25519MLKEM768KeyShare struct {
	dk      *mlkem.DecapsulationKey768
	xparams ecdheParameters
}

func (k *tls13X25519MLKEM768KeyShare) Group() CurveID { return X25519MLKEM768 }

// ClientHello.key_share.data = EK(1184) || X25519(32)
func (k *tls13X25519MLKEM768KeyShare) PublicKey() []byte {
	return slices.Concat(k.dk.EncapsulationKey().Bytes(), k.xparams.PublicKey())
}

// ServerHello.key_share.data = CT(1088) || X25519(32)
// SharedKey = KEM_ss || ECDHE_ss
func (k *tls13X25519MLKEM768KeyShare) SharedKey(serverShare []byte) ([]byte, error) {
	ct, sx := splitKeyShare(serverShare, mlkem768CTSize, x25519ShareSize)
	if ct == nil || sx == nil {
		return nil, errors.New("tls: invalid server share length for X25519MLKEM768")
	}

	kemSS, err := k.dk.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	if len(kemSS) != mlkemSSSize {
		return nil, errors.New("tls: invalid ML-KEM shared secret size")
	}

	ecdheSS := k.xparams.SharedKey(sx)
	if ecdheSS == nil {
		return nil, errors.New("tls: invalid server x25519 share")
	}

	return slices.Concat(kemSS, ecdheSS), nil
}

type tls13SecP256r1MLKEM768 struct {
	dk      *mlkem.DecapsulationKey768
	xparams ecdheParameters
}

func (k *tls13SecP256r1MLKEM768) Group() CurveID { return SecP256r1MLKEM768 }

// ClientHello.key_share.data = SecP256r1(65) || EK(1184)
func (k *tls13SecP256r1MLKEM768) PublicKey() []byte {
	// deliberately the reverse of X25519MLKEM768
	return slices.Concat(k.xparams.PublicKey(), k.dk.EncapsulationKey().Bytes())
}

// ServerHello.key_share.data = SecP256r1(65) || CT(1088)
// SharedKey = ECDHE_ss || KEM_ss
func (k *tls13SecP256r1MLKEM768) SharedKey(serverShare []byte) ([]byte, error) {
	sx, ct := splitKeyShare(serverShare, secP256r1ShareSize, mlkem768CTSize)
	if sx == nil || ct == nil {
		return nil, errors.New("tls: invalid server share length for SecP256r1MLKEM768")
	}

	kemSS, err := k.dk.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	if len(kemSS) != mlkemSSSize {
		return nil, errors.New("tls: invalid ML-KEM shared secret size")
	}

	ecdheSS := k.xparams.SharedKey(sx)
	if ecdheSS == nil {
		return nil, errors.New("tls: invalid server secp256r1 share")
	}

	return slices.Concat(ecdheSS, kemSS), nil
}

type tls13SecP384r1MLKEM1024 struct {
	dk      *mlkem.DecapsulationKey1024
	xparams ecdheParameters
}

func (k *tls13SecP384r1MLKEM1024) Group() CurveID { return SecP384r1MLKEM1024 }

// ClientHello.key_share.data = SecP384r1(97) || EK(1568)
func (k *tls13SecP384r1MLKEM1024) PublicKey() []byte {
	return slices.Concat(k.xparams.PublicKey(), k.dk.EncapsulationKey().Bytes())
}

// ServerHello.key_share.data = SecP384r1(97) || CT(1568)
// SharedKey = ECDHE_ss || KEM_ss
func (k *tls13SecP384r1MLKEM1024) SharedKey(serverShare []byte) ([]byte, error) {
	sx, ct := splitKeyShare(serverShare, secP384r1ShareSize, mlkem1024CTSize)
	if sx == nil || ct == nil {
		return nil, errors.New("tls: invalid server share length for SecP384r1MLKEM1024")
	}

	kemSS, err := k.dk.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	if len(kemSS) != mlkemSSSize {
		return nil, errors.New("tls: invalid ML-KEM shared secret size")
	}

	ecdheSS := k.xparams.SharedKey(sx)
	if ecdheSS == nil {
		return nil, errors.New("tls: invalid server secp384r1 share")
	}

	return slices.Concat(ecdheSS, kemSS), nil
}

type tls13MLKEM1024 struct {
	dk *mlkem.DecapsulationKey1024
}

func (k *tls13MLKEM1024) Group() CurveID { return MLKEM1024 }

// ClientHello.key_share.data = EK(1568)
func (k *tls13MLKEM1024) PublicKey() []byte {
	return k.dk.EncapsulationKey().Bytes()
}

// ServerHello.key_share.data = CT(1568)
// SharedKey = KEM_ss
func (k *tls13MLKEM1024) SharedKey(serverShare []byte) ([]byte, error) {
	ct := serverShare
	if ct == nil {
		return nil, errors.New("tls: invalid server share length for MLKEM1024")
	}

	kemSS, err := k.dk.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	if len(kemSS) != mlkemSSSize {
		return nil, errors.New("tls: invalid ML-KEM shared secret size")
	}

	return kemSS, nil
}

// mlkem.GenerateKey{768,1024} don't let us provide a custom source of
// randomness, so we do this instead
func NewDecapsulationKey768(rand io.Reader) (*mlkem.DecapsulationKey768, error) {
	seed := make([]byte, 64)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey768(seed)
}
func NewDecapsulationKey1024(rand io.Reader) (*mlkem.DecapsulationKey1024, error) {
	seed := make([]byte, 64)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey1024(seed)
}

func generateTLS13KeyShare(rand io.Reader, group CurveID) (tls13KeyShare, error) {
	switch group {
	case X25519MLKEM768:
		dk, err := NewDecapsulationKey768(rand)
		if err != nil {
			return nil, err
		}
		xp, err := generateECDHEParameters(rand, X25519)
		if err != nil {
			return nil, err
		}
		return &tls13X25519MLKEM768KeyShare{dk: dk, xparams: xp}, nil
	case SecP256r1MLKEM768:
		dk, err := NewDecapsulationKey768(rand)
		if err != nil {
			return nil, err
		}
		xp, err := generateECDHEParameters(rand, CurveP256)
		if err != nil {
			return nil, err
		}
		return &tls13SecP256r1MLKEM768{dk: dk, xparams: xp}, nil
	case SecP384r1MLKEM1024:
		dk, err := NewDecapsulationKey1024(rand)
		if err != nil {
			return nil, err
		}
		xp, err := generateECDHEParameters(rand, CurveP384)
		if err != nil {
			return nil, err
		}
		return &tls13SecP384r1MLKEM1024{dk: dk, xparams: xp}, nil
	case MLKEM1024:
		dk, err := NewDecapsulationKey1024(rand)
		if err != nil {
			return nil, err
		}
		return &tls13MLKEM1024{dk: dk}, nil
	default:
		if _, ok := curveForCurveID(group); group != X25519 && !ok {
			return nil, errors.New("tls: unsupported group")
		}
		p, err := generateECDHEParameters(rand, group)
		if err != nil {
			return nil, err
		}
		return &tls13ECDHEKeyShare{group: group, params: p}, nil
	}
}

func mlkemEncapsulate768(rand io.Reader, ek *mlkem.EncapsulationKey768) ([]byte, []byte, error) {
	randData := make([]byte, 32)
	if _, err := io.ReadFull(rand, randData); err != nil {
		return nil, nil, err
	}
	kemSS, ct, err := mlkemtest.Encapsulate768(ek, randData)
	if err != nil {
		return nil, nil, err
	}
	if len(ct) != mlkem768CTSize || len(kemSS) != mlkemSSSize {
		return nil, nil, errors.New("tls: invalid ML-KEM encapsulation output size")
	}
	return kemSS, ct, nil
}
func mlkemEncapsulate1024(rand io.Reader, ek *mlkem.EncapsulationKey1024) ([]byte, []byte, error) {
	randData := make([]byte, 32)
	if _, err := io.ReadFull(rand, randData); err != nil {
		return nil, nil, err
	}
	kemSS, ct, err := mlkemtest.Encapsulate1024(ek, randData)
	if err != nil {
		return nil, nil, err
	}
	if len(ct) != mlkem1024CTSize || len(kemSS) != mlkemSSSize {
		return nil, nil, errors.New("tls: invalid ML-KEM encapsulation output size")
	}
	return kemSS, ct, nil
}

func generateTLS13ServerShareAndSharedKey(rand io.Reader, group CurveID, clientShare []byte) ([]byte, []byte, error) {
	switch group {
	case X25519MLKEM768:
		// ClientHello.share = EK(1184) || X25519(32)
		ekBytes, cx := splitKeyShare(clientShare, mlkem768EKSize, x25519ShareSize)
		if ekBytes == nil || cx == nil {
			return nil, nil, errors.New("tls: invalid client share length for X25519MLKEM768")
		}

		ek, err := mlkem.NewEncapsulationKey768(ekBytes)
		if err != nil {
			return nil, nil, err
		}

		kemSS, ct, err := mlkemEncapsulate768(rand, ek)
		if err != nil {
			return nil, nil, err
		}

		sp, err := generateECDHEParameters(rand, X25519)
		if err != nil {
			return nil, nil, err
		}
		ecdheSS := sp.SharedKey(cx)
		if ecdheSS == nil {
			return nil, nil, errors.New("tls: invalid client x25519 share")
		}

		// ServerHello.share = CT(1088) || X25519(32)
		serverShare := slices.Concat(ct, sp.PublicKey())

		// shared = KEM_ss || ECDHE_ss
		shared := slices.Concat(kemSS, ecdheSS)
		return serverShare, shared, nil

	case SecP256r1MLKEM768:
		// ClientHello.share = SecP256r1(65) || EK(1184)
		cx, ekBytes := splitKeyShare(clientShare, secP256r1ShareSize, mlkem768EKSize)
		if cx == nil || ekBytes == nil {
			return nil, nil, errors.New("tls: invalid client share length for SecP256r1MLKEM768")
		}

		ek, err := mlkem.NewEncapsulationKey768(ekBytes)
		if err != nil {
			return nil, nil, err
		}

		kemSS, ct, err := mlkemEncapsulate768(rand, ek)
		if err != nil {
			return nil, nil, err
		}

		sp, err := generateECDHEParameters(rand, CurveP256)
		if err != nil {
			return nil, nil, err
		}
		ecdheSS := sp.SharedKey(cx)
		if ecdheSS == nil {
			return nil, nil, errors.New("tls: invalid client secp256r1 share")
		}

		// ServerHello.share = SecP256r1(65) || CT(1088)
		serverShare := slices.Concat(sp.PublicKey(), ct)

		// shared = ECDHE_ss || KEM_ss
		shared := slices.Concat(ecdheSS, kemSS)
		return serverShare, shared, nil

	case SecP384r1MLKEM1024:
		// ClientHello.share = SecP384r1(97) || EK(1568)
		cx, ekBytes := splitKeyShare(clientShare, secP384r1ShareSize, mlkem1024EKSize)
		if cx == nil || ekBytes == nil {
			return nil, nil, errors.New("tls: invalid client share length for SecP384r1MLKEM1024")
		}

		ek, err := mlkem.NewEncapsulationKey1024(ekBytes)
		if err != nil {
			return nil, nil, err
		}

		kemSS, ct, err := mlkemEncapsulate1024(rand, ek)
		if err != nil {
			return nil, nil, err
		}

		sp, err := generateECDHEParameters(rand, CurveP384)
		if err != nil {
			return nil, nil, err
		}
		ecdheSS := sp.SharedKey(cx)
		if ecdheSS == nil {
			return nil, nil, errors.New("tls: invalid client secp384r1 share")
		}

		// ServerHello.share = SecP384r1(97) || CT(1568)
		serverShare := slices.Concat(sp.PublicKey(), ct)

		// shared = ECDHE_ss || KEM_ss
		shared := slices.Concat(ecdheSS, kemSS)
		return serverShare, shared, nil

	case MLKEM1024:
		// ClientHello.share = EK(1568)
		ekBytes := clientShare
		if len(ekBytes) != mlkem1024EKSize {
			return nil, nil, errors.New("tls: invalid client share length for MLKEM1024")
		}

		ek, err := mlkem.NewEncapsulationKey1024(ekBytes)
		if err != nil {
			return nil, nil, err
		}

		kemSS, ct, err := mlkemEncapsulate1024(rand, ek)
		if err != nil {
			return nil, nil, err
		}

		// ServerHello.share = CT(1568)
		serverShare := ct

		// shared = KEM_ss
		shared := kemSS
		return serverShare, shared, nil

	default:
		// Classical TLS 1.3 ECDHE (X25519, P-256, P-384, P-521, etc.)
		if _, ok := curveForCurveID(group); group != X25519 && !ok {
			return nil, nil, errors.New("tls: unsupported selected group")
		}

		params, err := generateECDHEParameters(rand, group)
		if err != nil {
			return nil, nil, err
		}

		sharedKey := params.SharedKey(clientShare)
		if sharedKey == nil {
			return nil, nil, errors.New("tls: invalid client key share")
		}

		return params.PublicKey(), sharedKey, nil
	}
}
