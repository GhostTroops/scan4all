// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

// Only implemented client-side, for server certificates.
// Alternate certificate message formats (https://datatracker.ietf.org/doc/html/rfc7250) are not
// supported.
// https://datatracker.ietf.org/doc/html/rfc8879
type utlsCompressedCertificateMsg struct {
	raw []byte

	algorithm                    uint16
	uncompressedLength           uint32 // uint24
	compressedCertificateMessage []byte
}

func (m *utlsCompressedCertificateMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var b cryptobyte.Builder
	b.AddUint8(utlsTypeCompressedCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.algorithm)
		b.AddUint24(m.uncompressedLength)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressedCertificateMessage)
		})
	})

	var err error
	m.raw, err = b.Bytes()
	return m.raw, err
}

func (m *utlsCompressedCertificateMsg) unmarshal(data []byte) bool {
	*m = utlsCompressedCertificateMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.algorithm) ||
		!s.ReadUint24(&m.uncompressedLength) ||
		!readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}
	return true
}

type utlsEncryptedExtensionsMsgExtraFields struct {
	hasApplicationSettings bool
	applicationSettings    []byte
	customExtension        []byte
}

func (m *encryptedExtensionsMsg) utlsUnmarshal(extension uint16, extData cryptobyte.String) bool {
	switch extension {
	case utlsExtensionApplicationSettings:
		m.utls.hasApplicationSettings = true
		m.utls.applicationSettings = []byte(extData)
	}
	return true // success/unknown extension
}

type utlsClientEncryptedExtensionsMsg struct {
	raw                    []byte
	applicationSettings    []byte
	hasApplicationSettings bool
	customExtension        []byte
}

func (m *utlsClientEncryptedExtensionsMsg) marshal() (x []byte, err error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var builder cryptobyte.Builder
	builder.AddUint8(typeEncryptedExtensions)
	builder.AddUint24LengthPrefixed(func(body *cryptobyte.Builder) {
		body.AddUint16LengthPrefixed(func(extensions *cryptobyte.Builder) {
			if m.hasApplicationSettings {
				extensions.AddUint16(utlsExtensionApplicationSettings)
				extensions.AddUint16LengthPrefixed(func(msg *cryptobyte.Builder) {
					msg.AddBytes(m.applicationSettings)
				})
			}
			if len(m.customExtension) > 0 {
				extensions.AddUint16(utlsFakeExtensionCustom)
				extensions.AddUint16LengthPrefixed(func(msg *cryptobyte.Builder) {
					msg.AddBytes(m.customExtension)
				})
			}
		})
	})

	m.raw, err = builder.Bytes()
	return m.raw, err
}

func (m *utlsClientEncryptedExtensionsMsg) unmarshal(data []byte) bool {
	*m = utlsClientEncryptedExtensionsMsg{raw: data}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case utlsExtensionApplicationSettings:
			m.hasApplicationSettings = true
			m.applicationSettings = []byte(extData)
		default:
			// Unknown extensions are illegal in EncryptedExtensions.
			return false
		}
	}
	return true
}
