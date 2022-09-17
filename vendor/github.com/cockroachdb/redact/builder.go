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
	"io"
	"unicode/utf8"
)

// StringBuilder accumulates strings with optional redaction markers.
//
// It implements io.Writer but marks direct writes as redactable.
// To distinguish safe and unsafe bits, it also implements the SafeWriter
// interface.
type StringBuilder struct {
	// we use bytes.Buffer internally to simplify the implementation of
	// the SafeWriter interface.
	buf bytes.Buffer
}

// String returns the accumulated string, with redaction markers stripped out.
// To obtain the redactable string, call RedactableString().
func (b StringBuilder) String() string { return b.RedactableString().StripMarkers() }

var _ fmt.Stringer = StringBuilder{}
var _ fmt.Stringer = (*StringBuilder)(nil)

// RedactableString returns the accumulated string, including redaction markers.
func (b StringBuilder) RedactableString() RedactableString { return RedactableString(b.buf.String()) }

// RedactableBytes returns the accumulated bytes, including redaction markers.
func (b StringBuilder) RedactableBytes() RedactableBytes { return RedactableBytes(b.buf.Bytes()) }

// SafeFormat implements SafeFormatter.
func (b StringBuilder) SafeFormat(p SafePrinter, _ rune) {
	// We only support the %v / %s natural print here.
	// Go supports other formatting verbs for strings: %x/%X/%q.
	//
	// We don't do this here, keeping in mind that the output
	// of a SafeFormat must remain a redactable string.
	//
	// %x/%X cannot be implemented because they would turn redaction
	//       markers into hex codes, and the entire result string would
	//       appear safe for reporting, which would break the semantics
	//       of this package.
	//
	// %q    cannot be implemented because it replaces non-ASCII characters
	//       with numeric unicode escapes, which breaks redaction
	//       markers too.
	p.Print(b.RedactableString())
}

var _ SafeFormatter = StringBuilder{}
var _ SafeFormatter = (*StringBuilder)(nil)

// Len returns the number of accumulated bytes, including redaction
// markers; b.Len() == len(b.RedactableString()).
func (b *StringBuilder) Len() int { return b.buf.Len() }

// Cap returns the capacity of the builder's underlying byte slice. It is the
// total space allocated for the string being built and includes any bytes
// already written.
func (b *StringBuilder) Cap() int { return b.buf.Cap() }

// Reset resets the Builder to be empty.
func (b *StringBuilder) Reset() { b.buf.Reset() }

// StringBuilder implements io.Writer.
// Direct Write() calls are considered unsafe.
var _ io.Writer = (*StringBuilder)(nil)

// Write implements the io.Writer interface.
func (b *StringBuilder) Write(s []byte) (int, error) {
	b.UnsafeBytes(s)
	return len(s), nil
}

// StringBuilder implements SafeWriter.
var _ SafeWriter = (*StringBuilder)(nil)

// Print is part of the SafeWriter interface.
func (b *StringBuilder) Print(args ...interface{}) {
	_, _ = Fprint(&b.buf, args...)
}

// Printf is part of the SafeWriter interface.
func (b *StringBuilder) Printf(format string, args ...interface{}) {
	_, _ = Fprintf(&b.buf, format, args...)
}

// SafeString is part of the SafeWriter interface.
func (b *StringBuilder) SafeString(s SafeString) {
	w := escapeWriter{w: &b.buf, enclose: false}
	_, _ = w.Write([]byte(s))
}

// SafeRune is part of the SafeWriter interface.
func (b *StringBuilder) SafeRune(s SafeRune) {
	if s == startRedactable || s == endRedactable {
		s = escapeMark
	}
	_, _ = b.buf.WriteRune(rune(s))
}

// UnsafeString is part of the SafeWriter interface.
func (b *StringBuilder) UnsafeString(s string) {
	w := escapeWriter{w: &b.buf, enclose: true, strip: true}
	_, _ = w.Write([]byte(s))
}

// UnsafeRune is part of the SafeWriter interface.
func (b *StringBuilder) UnsafeRune(s rune) {
	_, _ = b.buf.WriteRune(startRedactable)
	b.SafeRune(SafeRune(s))
	_, _ = b.buf.WriteRune(endRedactable)
}

// UnsafeByte is part of the SafeWriter interface.
func (b *StringBuilder) UnsafeByte(s byte) {
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
func (b *StringBuilder) UnsafeBytes(s []byte) {
	w := escapeWriter{w: &b.buf, enclose: true, strip: true}
	_, _ = w.Write(s)
}
