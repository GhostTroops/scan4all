// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// macOS arm and arm64 with cgo use the embedded roots in root_darwin_armx.go.
// Every other macOS build, including arm64 with cgo disabled, uses execSecurityRoots.
// iOS keeps the previous split: cgo uses the embedded roots, and this file stays out.

//go:build !ios && (!cgo || (!arm && !arm64))
// +build !ios
// +build !cgo !arm,!arm64

package x509

func loadSystemRoots() (*CertPool, error) {
	return execSecurityRoots()
}
