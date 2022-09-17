// Copyright 2020 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package redact

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

// printer implements SafePrinter.
// This is the machinery for the Print() functions offered
// by this package.
type printer struct {
	escapeState
	buf bytes.Buffer
}

var _ fmt.State = (*printer)(nil)
var _ SafeWriter = (*printer)(nil)

// Print is part of the SafeWriter interface.
func (b *printer) Print(args ...interface{}) {
	_, _ = Fprint(&b.buf, args...)
}

// Printf is part of the SafeWriter interface.
func (b *printer) Printf(format string, args ...interface{}) {
	_, _ = Fprintf(&b.buf, format, args...)
}

// SafeString is part of the SafeWriter interface.
func (b *printer) SafeString(s SafeString) {
	w := escapeWriter{w: &b.buf, enclose: false}
	_, _ = w.Write([]byte(s))
}

// SafeRune is part of the SafeWriter interface.
func (b *printer) SafeRune(s SafeRune) {
	if s == startRedactable || s == endRedactable {
		s = escapeMark
	}
	_, _ = b.buf.WriteRune(rune(s))
}

// UnsafeString is part of the SafeWriter interface.
func (b *printer) UnsafeString(s string) {
	w := escapeWriter{w: &b.buf, enclose: true, strip: true}
	_, _ = w.Write([]byte(s))
}

// UnsafeRune is part of the SafeWriter interface.
func (b *printer) UnsafeRune(s rune) {
	_, _ = b.buf.WriteRune(startRedactable)
	b.SafeRune(SafeRune(s))
	_, _ = b.buf.WriteRune(endRedactable)
}

// UnsafeByte is part of the SafeWriter interface.
func (b *printer) UnsafeByte(s byte) {
	_, _ = b.buf.WriteRune(startRedactable)
	if s >= utf8.RuneSelf ||
		s == startRedactableBytes[0] || s == endRedactableBytes[0] {
		// Unsafe byte. Escape it.
		_, _ = b.buf.Write(escapeBytes)
	} else {
		_ = b.buf.WriteByte(s)
	}
	_, _ = b.buf.WriteRune(endRedactable)
}

// UnsafeBytes is part of the SafeWriter interface.
func (b *printer) UnsafeBytes(s []byte) {
	w := escapeWriter{w: &b.buf, enclose: true, strip: true}
	_, _ = w.Write(s)
}
