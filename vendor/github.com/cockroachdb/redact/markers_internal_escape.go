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
)

// escapeState abstracts on top of fmt.State and ensures that call
// calls to Write() enclose the writtne bytes between unsafe markers.
type escapeState struct {
	fmt.State
	w escapeWriter
}

var _ fmt.State = (*escapeState)(nil)

func makeEscapeState(s fmt.State, buf *bytes.Buffer) escapeState {
	e := escapeState{State: s}
	e.w = escapeWriter{w: buf, enclose: true}
	return e
}

// Write is part of the fmt.State interface and implements the io.Writer interface.
func (p *escapeState) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

// escapeWriter abstracts on top of io.Writer and ensures that all
// calls to Write() escape markers.
// Also, final spaces and newlines are stripped if strip is set.
// Also, the overall result is enclosed inside redaction markers
// if enclose is true.
type escapeWriter struct {
	w       io.Writer
	enclose bool
	strip   bool
}

var _ io.Writer = (*escapeWriter)(nil)

// Write implements the io.Writer interface.
func (p *escapeWriter) Write(b []byte) (int, error) {
	st := escapeResult{0, nil}

	if p.strip {
		// Trim final newlines/spaces, for convenience.
		end := len(b)
		for i := end - 1; i >= 0; i-- {
			if b[i] == '\n' || b[i] == ' ' {
				end = i
			} else {
				break
			}
		}
		b = b[:end]
	}

	// Here we could choose to omit the output
	// entirely if there was nothing but empty space:
	// if len(b) == 0 { return 0, nil }

	// Note: we use len(...RedactableS) and not len(...RedactableBytes)
	// because the ...S variant is a compile-time constant so this
	// accelerates the loops below.
	start, ls := startRedactableBytes, len(startRedactableS)
	end, le := endRedactableBytes, len(endRedactableS)
	escape := escapeBytes

	if p.enclose {
		st = p.doWrite(start, st, false)
	}

	// Now write the string.

	// k is the index in b up to (and excluding) the byte which we've
	// already copied into the output.
	k := 0

	for i := 0; i < len(b); i++ {
		if b[i] == '\n' && p.enclose {
			// Avoid enclosing newline characters inside redaction markers.
			// This is important when redact is used to render errors, where
			// sub-strings split at newline characters are rendered
			// separately.
			st = p.doWrite(b[k:i], st, true)
			st = p.doWrite(end, st, false)
			// Advance to the last newline character. We want to forward
			// them all in a single call to doWrite, for performance.
			lastNewLine := i
			for b[lastNewLine] == '\n' && lastNewLine < len(b) {
				lastNewLine++
			}
			st = p.doWrite(b[i:lastNewLine], st, true)
			st = p.doWrite(start, st, false)
			// Advance the counters by the number of newline characters.
			k = lastNewLine
			i = lastNewLine - 1 /* -1 because we have i++ at the end of every iteration */
		} else {
			// Ensure that occurrences of the delimiter inside the string get
			// escaped.
			// Reminder: ls and le are likely greater than 1, as we are scanning
			// utf-8 encoded delimiters (the utf-8 encoding is multibyte).
			if i+ls <= len(b) && bytes.Equal(b[i:i+ls], start) {
				st = p.doWrite(b[k:i], st, true)
				st = p.doWrite(escape, st, false)
				// Advance the counters by the length (in bytes) of the delimiter.
				st.l += ls
				k = i + ls
				i += ls - 1 /* -1 because we have i++ at the end of every iteration */
			} else if i+le <= len(b) && bytes.Equal(b[i:i+le], end) {
				st = p.doWrite(b[k:i], st, true)
				st = p.doWrite(escape, st, false)
				// Advance the counters by the length (in bytes) of the delimiter.
				st.l += le
				k = i + le
				i += le - 1 /* -1 because we have i++ at the end of every iteration */
			}
		}
	}
	st = p.doWrite(b[k:], st, true)
	if p.enclose {
		st = p.doWrite(end, st, false)
	}
	return st.l, st.err
}

type escapeResult struct {
	l   int
	err error
}

func (p *escapeWriter) doWrite(b []byte, st escapeResult, count bool) escapeResult {
	if st.err != nil {
		// An error was encountered previously.
		// No-op.
		return st
	}
	sz, err := p.w.Write(b)
	if count {
		st.l += sz
	}
	st.err = err
	return st
}

// internalEscapeBytes escapes redaction markers in the provided buf
// starting at the location startLoc.
// The bytes before startLoc are considered safe (already escaped).
func internalEscapeBytes(b []byte, startLoc int) (res []byte) {
	// Note: we use len(...RedactableS) and not len(...RedactableBytes)
	// because the ...S variant is a compile-time constant so this
	// accelerates the loops below.
	start, ls := startRedactableBytes, len(startRedactableS)
	end, le := endRedactableBytes, len(endRedactableS)
	escape := escapeBytes

	// res is the output slice. In the common case where there is
	// nothing to escape, the input slice is returned directly
	// and no allocation takes place.
	res = b
	// copied is true if and only if `res` is a copy of `b`.  It only
	// turns to true if the loop below finds something to escape.
	copied := false
	// k is the index in b up to (and excluding) the byte which we've
	// already copied into res (if copied=true).
	k := 0

	for i := startLoc; i < len(b); i++ {
		// Ensure that occurrences of the delimiter inside the string get
		// escaped.
		// Reminder: ls and le are likely greater than 1, as we are scanning
		// utf-8 encoded delimiters (the utf-8 encoding is multibyte).
		if i+ls <= len(b) && bytes.Equal(b[i:i+ls], start) {
			if !copied {
				// We only allocate an output slice when we know we definitely
				// need it.
				res = make([]byte, 0, len(b)+len(escape))
				copied = true
			}
			res = append(res, b[k:i]...)
			res = append(res, escape...)
			// Advance the counters by the length (in bytes) of the delimiter.
			k = i + ls
			i += ls - 1 /* -1 because we have i++ at the end of every iteration */
		} else if i+le <= len(b) && bytes.Equal(b[i:i+le], end) {
			if !copied {
				// See the comment above about res allocation.
				res = make([]byte, 0, len(b)+len(escape))
				copied = true
			}
			res = append(res, b[k:i]...)
			res = append(res, escape...)
			// Advance the counters by the length (in bytes) of the delimiter.
			k = i + le
			i += le - 1 /* -1 because we have i++ at the end of every iteration */
		}
	}
	if copied {
		res = append(res, b[k:]...)
	}
	return
}
