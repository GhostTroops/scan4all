// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Fingerprinter is a struct largely for holding options for the FingerprintClientHello func
type Fingerprinter struct {
	// AllowBluntMimicry will ensure that unknown extensions are
	// passed along into the resulting ClientHelloSpec as-is
	// It will not ensure that the PSK is passed along, if you require that, use KeepPSK
	// WARNING: there could be numerous subtle issues with ClientHelloSpecs
	// that are generated with this flag which could compromise security and/or mimicry
	AllowBluntMimicry bool
	// AlwaysAddPadding will always add a UtlsPaddingExtension with BoringPaddingStyle
	// at the end of the extensions list if it isn't found in the fingerprinted hello.
	// This could be useful in scenarios where the hello you are fingerprinting does not
	// have any padding, but you suspect that other changes you make to the final hello
	// (including things like different SNI lengths) would cause padding to be necessary
	AlwaysAddPadding bool

	RealPSKResumption bool // if set, PSK extension (if any) will be real PSK extension, otherwise it will be fake PSK extension
}

// FingerprintClientHello returns a ClientHelloSpec which is based on the
// ClientHello that is passed in as the data argument
//
// If the ClientHello passed in has extensions that are not recognized or cannot be handled
// it will return a non-nil error and a nil *ClientHelloSpec value
//
// The data should be the full tls record, including the record type/version/length header
// as well as the handshake type/length/version header
// https://tools.ietf.org/html/rfc5246#section-6.2
// https://tools.ietf.org/html/rfc5246#section-7.4
//
// It calls UnmarshalClientHello internally, and is kept for backwards compatibility
func (f *Fingerprinter) FingerprintClientHello(data []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	return f.RawClientHello(data)
}

// RawClientHello returns a ClientHelloSpec which is based on the
// ClientHello raw bytes that is passed in as the raw argument.
//
// It was renamed from FingerprintClientHello in v1.3.1 and earlier versions
// as a more precise name for the function
func (f *Fingerprinter) RawClientHello(raw []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	clientHelloSpec = &ClientHelloSpec{}

	err = clientHelloSpec.FromRaw(raw, f.AllowBluntMimicry, f.RealPSKResumption)
	if err != nil {
		return nil, err
	}

	if f.AlwaysAddPadding {
		clientHelloSpec.AlwaysAddPadding()
	}

	return clientHelloSpec, nil
}

// UnmarshalJSONClientHello returns a ClientHelloSpec which is based on the
// ClientHello JSON bytes that is passed in as the json argument.
func (f *Fingerprinter) UnmarshalJSONClientHello(json []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	clientHelloSpec = &ClientHelloSpec{}
	err = clientHelloSpec.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}

	if f.AlwaysAddPadding {
		clientHelloSpec.AlwaysAddPadding()
	}

	return clientHelloSpec, nil
}
