package tls

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/refraction-networking/utls/dicttls"
	"github.com/refraction-networking/utls/internal/hpke"
	"golang.org/x/crypto/cryptobyte"
)

// Unstable API: This is a work in progress and may change in the future. Using
// it in your application may cause your application to break when updating to
// a new version of uTLS.

const (
	OuterClientHello byte = 0x00
	InnerClientHello byte = 0x01
)

type EncryptedClientHelloExtension interface {
	// TLSExtension must be implemented by all EncryptedClientHelloExtension implementations.
	TLSExtension

	// MarshalClientHello is called by (*UConn).MarshalClientHello() when an ECH extension
	// is present to allow the ECH extension to take control of the generation of the
	// entire ClientHello message.
	MarshalClientHello(*UConn) error

	mustEmbedUnimplementedECHExtension()
}

type ECHExtension = EncryptedClientHelloExtension // alias

// type guard: GREASEEncryptedClientHelloExtension must implement EncryptedClientHelloExtension
var (
	_ EncryptedClientHelloExtension = (*GREASEEncryptedClientHelloExtension)(nil)

	_ EncryptedClientHelloExtension = (*UnimplementedECHExtension)(nil)
)

type GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites []HPKESymmetricCipherSuite
	cipherSuite           HPKESymmetricCipherSuite // randomly picked from CandidateCipherSuites or generated if empty
	CandidateConfigIds    []uint8
	configId              uint8    // randomly picked from CandidateConfigIds or generated if empty
	EncapsulatedKey       []byte   // if empty, will generate random bytes
	CandidatePayloadLens  []uint16 // Pre-encryption. If 0, will pick 128(+16=144)
	payload               []byte   // payload should be calculated ONCE and stored here, HRR will reuse this

	initOnce sync.Once

	UnimplementedECHExtension
}

type GREASEECHExtension = GREASEEncryptedClientHelloExtension // alias

// init initializes the GREASEEncryptedClientHelloExtension with random values if they are not set.
//
// Based on cloudflare/go's echGenerateGreaseExt()
func (g *GREASEEncryptedClientHelloExtension) init() error {
	var initErr error
	g.initOnce.Do(func() {
		// Set the config_id field to a random byte.
		//
		// Note: must not reuse this extension unless for HRR. It is required
		// to generate new random bytes for config_id for each new ClientHello,
		// but reuse the same config_id for HRR.
		if len(g.CandidateConfigIds) == 0 {
			var b []byte = make([]byte, 1)
			_, err := rand.Read(b[:])
			if err != nil {
				initErr = fmt.Errorf("error generating random byte for config_id: %w", err)
				return
			}
			g.configId = b[0]
		} else {
			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateConfigIds))))
			if err != nil {
				initErr = fmt.Errorf("error generating random index for config_id: %w", err)
				return
			}
			g.configId = g.CandidateConfigIds[rndIndex.Int64()]
		}

		// Set the cipher_suite field to a supported HpkeSymmetricCipherSuite.
		// The selection SHOULD vary to exercise all supported configurations,
		// but MAY be held constant for successive connections to the same server
		// in the same session.
		if len(g.CandidateCipherSuites) == 0 {
			g.cipherSuite = HPKESymmetricCipherSuite{uint16(defaultHpkeKdf), uint16(defaultHpkeAead)}
		} else {
			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateCipherSuites))))
			if err != nil {
				initErr = fmt.Errorf("error generating random index for cipher_suite: %w", err)
				return
			}
			g.cipherSuite = HPKESymmetricCipherSuite{
				g.CandidateCipherSuites[rndIndex.Int64()].KdfId,
				g.CandidateCipherSuites[rndIndex.Int64()].AeadId,
			}
			// aead = hpke.AEAD(g.cipherSuite.AeadId)
		}

		if len(g.EncapsulatedKey) == 0 {
			kem := uint16(defaultHpkeKem)

			echPK, err := hpke.ParseHPKEPublicKey(uint16(kem), dummyX25519PublicKey)
			if err != nil {
				initErr = fmt.Errorf("tls: grease ech: failed to parse dummy public key: %w", err)
				return
			}
			suite := echCipher{
				KDFID:  defaultHpkeKdf,
				AEADID: defaultHpkeAead,
			}
			g.EncapsulatedKey, _, err = hpke.SetupSender(kem, suite.KDFID, suite.AEADID, echPK, []byte{})
			if err != nil {
				initErr = fmt.Errorf("tls: grease ech: failed to setup encapsulated key: %w", err)
				return
			}
		}

		if len(g.payload) == 0 {
			if len(g.CandidatePayloadLens) == 0 {
				g.CandidatePayloadLens = []uint16{128}
			}

			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidatePayloadLens))))
			if err != nil {
				initErr = fmt.Errorf("error generating random index for payload length: %w", err)
				return
			}

			initErr = g.randomizePayload(g.CandidatePayloadLens[rndIndex.Int64()])
		}
	})

	return initErr
}

func (g *GREASEEncryptedClientHelloExtension) randomizePayload(encodedHelloInnerLen uint16) error {
	if len(g.payload) != 0 {
		return errors.New("tls: grease ech: regenerating payload is forbidden")
	}

	g.payload = make([]byte, cipherLen(g.cipherSuite.AeadId, int(encodedHelloInnerLen)))
	_, err := rand.Read(g.payload)
	if err != nil {
		return fmt.Errorf("tls: generating grease ech payload: %w", err)
	}
	return nil
}

// writeToUConn implements TLSExtension.
//
// For ECH extensions, writeToUConn simply points the ech field in UConn to the extension.
func (g *GREASEEncryptedClientHelloExtension) writeToUConn(uconn *UConn) error {
	uconn.ech = g
	return uconn.MarshalClientHelloNoECH()
}

// Len implements TLSExtension.
func (g *GREASEEncryptedClientHelloExtension) Len() int {
	g.init()
	return 2 + 2 + 1 /* ClientHello Type */ + 4 /* CipherSuite */ + 1 /* Config ID */ + 2 + len(g.EncapsulatedKey) + 2 + len(g.payload)
}

// Read implements TLSExtension.
func (g *GREASEEncryptedClientHelloExtension) Read(b []byte) (int, error) {
	if len(b) < g.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(utlsExtensionECH >> 8)
	b[1] = byte(utlsExtensionECH & 0xFF)
	b[2] = byte((g.Len() - 4) >> 8)
	b[3] = byte((g.Len() - 4) & 0xFF)
	b[4] = OuterClientHello
	b[5] = byte(g.cipherSuite.KdfId >> 8)
	b[6] = byte(g.cipherSuite.KdfId & 0xFF)
	b[7] = byte(g.cipherSuite.AeadId >> 8)
	b[8] = byte(g.cipherSuite.AeadId & 0xFF)
	b[9] = g.configId
	b[10] = byte(len(g.EncapsulatedKey) >> 8)
	b[11] = byte(len(g.EncapsulatedKey) & 0xFF)
	copy(b[12:], g.EncapsulatedKey)
	b[12+len(g.EncapsulatedKey)] = byte(len(g.payload) >> 8)
	b[12+len(g.EncapsulatedKey)+1] = byte(len(g.payload) & 0xFF)
	copy(b[12+len(g.EncapsulatedKey)+2:], g.payload)

	return g.Len(), io.EOF
}

// MarshalClientHello implements EncryptedClientHelloExtension.
func (*GREASEEncryptedClientHelloExtension) MarshalClientHello(*UConn) error {
	return errors.New("tls: grease ech: MarshalClientHello() is not implemented, use (*UConn).MarshalClientHello() instead")
}

// Write implements TLSExtensionWriter.
func (g *GREASEEncryptedClientHelloExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)

	// Check the extension type, it must be OuterClientHello otherwise we are not
	// parsing the correct extension
	var chType uint8 // 0: outer, 1: inner
	var ignored cryptobyte.String
	if !extData.ReadUint8(&chType) || chType != 0 {
		return fullLen, errors.New("bad Client Hello type, expected 0, got " + fmt.Sprintf("%d", chType))
	}

	// Parse the cipher suite
	if !extData.ReadUint16(&g.cipherSuite.KdfId) || !extData.ReadUint16(&g.cipherSuite.AeadId) {
		return fullLen, errors.New("bad cipher suite")
	}
	if g.cipherSuite.KdfId != dicttls.HKDF_SHA256 &&
		g.cipherSuite.KdfId != dicttls.HKDF_SHA384 &&
		g.cipherSuite.KdfId != dicttls.HKDF_SHA512 {
		return fullLen, errors.New("bad KDF ID: " + fmt.Sprintf("%d", g.cipherSuite.KdfId))
	}
	if g.cipherSuite.AeadId != dicttls.AEAD_AES_128_GCM &&
		g.cipherSuite.AeadId != dicttls.AEAD_AES_256_GCM &&
		g.cipherSuite.AeadId != dicttls.AEAD_CHACHA20_POLY1305 {
		return fullLen, errors.New("bad AEAD ID: " + fmt.Sprintf("%d", g.cipherSuite.AeadId))
	}
	g.CandidateCipherSuites = []HPKESymmetricCipherSuite{g.cipherSuite}

	// GREASE the ConfigId
	if !extData.ReadUint8(&g.configId) {
		return fullLen, errors.New("bad config ID")
	}
	// we don't write to CandidateConfigIds because we don't really want to reuse the same config_id

	// GREASE the EncapsulatedKey
	if !extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("bad encapsulated key")
	}
	g.EncapsulatedKey = make([]byte, len(ignored))
	n, err := rand.Read(g.EncapsulatedKey)
	if err != nil {
		return fullLen, fmt.Errorf("tls: generating grease ech encapsulated key: %w", err)
	}
	if n != len(g.EncapsulatedKey) {
		return fullLen, fmt.Errorf("tls: generating grease ech encapsulated key: short read for %d bytes", len(ignored)-n)
	}

	// GREASE the payload
	if !extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("bad payload")
	}
	g.CandidatePayloadLens = []uint16{uint16(len(ignored) - cipherLen(g.cipherSuite.AeadId, 0))}

	return fullLen, nil
}

// UnimplementedECHExtension is a placeholder for an ECH extension that is not implemented.
// All implementations of EncryptedClientHelloExtension should embed this struct to ensure
// forward compatibility.
type UnimplementedECHExtension struct{}

// writeToUConn implements TLSExtension.
func (*UnimplementedECHExtension) writeToUConn(_ *UConn) error {
	return errors.New("tls: unimplemented ECHExtension")
}

// Len implements TLSExtension.
func (*UnimplementedECHExtension) Len() int {
	return 0
}

// Read implements TLSExtension.
func (*UnimplementedECHExtension) Read(_ []byte) (int, error) {
	return 0, errors.New("tls: unimplemented ECHExtension")
}

// MarshalClientHello implements EncryptedClientHelloExtension.
func (*UnimplementedECHExtension) MarshalClientHello(*UConn) error {
	return errors.New("tls: unimplemented ECHExtension")
}

// mustEmbedUnimplementedECHExtension is a noop function but is required to
// ensure forward compatibility.
func (*UnimplementedECHExtension) mustEmbedUnimplementedECHExtension() {
	panic("mustEmbedUnimplementedECHExtension() is not implemented")
}

// BoringGREASEECH returns a GREASE scheme BoringSSL uses by default.
func BoringGREASEECH() *GREASEEncryptedClientHelloExtension {
	return &GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: []HPKESymmetricCipherSuite{
			{
				KdfId:  dicttls.HKDF_SHA256,
				AeadId: dicttls.AEAD_AES_128_GCM,
			},
		},
		CandidatePayloadLens: []uint16{128, 160, 192, 224}, // +16: 144, 176, 208, 240
	}
}
