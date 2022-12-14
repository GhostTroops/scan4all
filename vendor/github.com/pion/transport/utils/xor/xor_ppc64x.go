// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ppc64 || ppc64le

// Package xor provides utility functions used by other Pion
// packages. PPC64 arch.
package xor

// XorBytes xors the bytes in a and b. The destination should have enough
// space, otherwise xorBytes will panic. Returns the number of bytes xor'd.
//revive:disable-next-line
func XorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	_ = dst[n-1]
	xorBytesVSX(&dst[0], &a[0], &b[0], n)
	return n
}

//go:noescape
func xorBytesVSX(dst, a, b *byte, n int)
