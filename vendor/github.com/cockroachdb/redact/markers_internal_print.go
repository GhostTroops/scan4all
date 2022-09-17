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
	"fmt"

	internalFmt "github.com/cockroachdb/redact/internal"
)

// printArgFn is the hook injected into the standard fmt logic
// by the printer functions in markers_print.go.
func printArgFn(p *internalFmt.InternalPrinter, arg interface{}, verb rune) (newState int) {
	redactLastWrites(p)

	switch verb {
	case 'T':
		// If the value was wrapped, reveal its original type. Anything else is not very useful.
		switch v := arg.(type) {
		case safeWrapper:
			arg = v.a
		case unsafeWrap:
			arg = v.a
		}

		// Shortcut: %T is always safe to print as-is.
		internalFmt.PrintArg(p, arg, verb)
		return len(internalFmt.Buf(p))
	case 'p':
		// Printing a pointer via %p is handled as special case in printf,
		// so we need a special case here too. The other cases of
		// printing a pointer via %v / %d %x etc is handled by the common path.

		switch v := arg.(type) {
		case safeWrapper:
			// If the value was meant to be safe, then print it as-is.
			internalFmt.PrintArg(p, v.a, verb)
			return len(internalFmt.Buf(p))

		case unsafeWrap:
			// If it's been wrapped, unwrap it. This helps preserve the
			// original pointer value in the output.
			arg = v.a
		}
		// Now perform an unsafe print: we are assuming that the pointer
		// representation by the fmt.printf code does not contain
		// redaction markers, and go a short route. If that assumption did
		// not hold (or is invalidated by changes upstream after this
		// comment is written), this code should be changed to use the
		// escapeWriter instead.
		internalFmt.Append(p, startRedactableBytes)
		internalFmt.PrintArg(p, arg, verb)
		internalFmt.Append(p, endRedactableBytes)
		return len(internalFmt.Buf(p))
	}

	// nil arguments are printed as-is. Note: a nil argument under
	// interface{} is not the same as a nil pointer passed via a pointer
	// of a concrete type. The latter kind of nil goes through
	// redaction as usual, because it may have its own custom Format() method.
	if arg == nil {
		internalFmt.PrintArg(p, arg, verb)
		return len(internalFmt.Buf(p))
	}

	// RedactableBytes/RedactableString are already formatted as
	// redactable. Include them as-is.
	//
	// NB: keep this logic synchronized with
	// (RedactableString/Bytes).SafeFormat().
	switch v := arg.(type) {
	case RedactableString:
		internalFmt.Append(p, []byte(v))
		return len(internalFmt.Buf(p))
	case RedactableBytes:
		internalFmt.Append(p, []byte(v))
		return len(internalFmt.Buf(p))
	}

	arg = annotateArg(arg, internalFmt.CollectingError(p))
	internalFmt.PrintArg(p, arg, verb)
	return len(internalFmt.Buf(p))
}

// redactLastWrites escapes any markers that were added by the
// internals of the printf functions, for example
// if markers were present in the format string.
func redactLastWrites(p *internalFmt.InternalPrinter) {
	state := internalFmt.GetState(p)
	newBuf := internalEscapeBytes(internalFmt.Buf(p), state)
	internalFmt.SetState(p, newBuf)
}

// annotateArg wraps the arguments to one of the print functions with
// an indirect formatter which ensures that redaction markers inside
// the representation of the object are escaped, and optionally
// encloses the result of the display between redaction markers.
//
// collectingError is true iff we are in the context of
// HelperForErrorf, where we want the %w verb to work properly. This
// adds a little overhead to the processing, but this is OK because
// typically the error path is not perf-critical.
func annotateArg(arg interface{}, collectingError bool) interface{} {
	var newArg fmt.Formatter
	err, isError := arg.(error)

	switch v := arg.(type) {
	case SafeFormatter:
		// calls to Format() by fmt.Print will be redirected to
		// v.SafeFormat(). This delegates the task of adding markers to
		// the object itself.
		newArg = &redactFormatRedirect{
			func(p SafePrinter, verb rune) { v.SafeFormat(p, verb) },
		}

	case SafeValue:
		// calls to Format() by fmt.Print will be redirected to a
		// display of v without redaction markers.
		//
		// Note that we can't let the value be displayed as-is because
		// we must prevent any marker inside the value from leaking into
		// the result. (We want to avoid mismatched markers.)
		newArg = &escapeArg{arg: arg, enclose: false}

	case SafeMessager:
		// Obsolete interface.
		// TODO(knz): Remove this.
		newArg = &escapeArg{arg: v.SafeMessage(), enclose: false}

	default:
		if isError && redactErrorFn != nil {
			// We place this case after the other cases above, in case
			// the error object knows how to print itself safely already.
			newArg = &redactFormatRedirect{
				func(p SafePrinter, verb rune) { redactErrorFn(err, p, verb) },
			}
		} else {
			// calls to Format() by fmt.Print will be redirected to a
			// display of v within redaction markers if the type is
			// considered unsafe, without markers otherwise. In any case,
			// occurrences of delimiters within are escaped.
			newArg = &escapeArg{arg: v, enclose: !isSafeValue(v)}
		}
	}

	if isError && collectingError {
		// Ensure the arg still implements the `error` interface for
		// detection by the handling of %w, while also implementing
		// fmt.Formatter to forward the implementation to the objects
		// constructed above.
		newArg = &makeError{err: err, arg: newArg}
	}

	return newArg
}

type makeError struct {
	err error
	arg fmt.Formatter
}

// Error implements error.
func (m *makeError) Error() string { return m.err.Error() }

// Format implements fmt.Formatter.
func (m *makeError) Format(f fmt.State, verb rune) { m.arg.Format(f, verb) }

// redactFormatRedirect wraps a safe print callback and uses it to
// implement fmt.Formatter.
type redactFormatRedirect struct {
	printFn func(p SafePrinter, verb rune)
}

// Format implements fmt.Formatter.
func (r *redactFormatRedirect) Format(s fmt.State, verb rune) {
	defer func() {
		if p := recover(); p != nil {
			e := escapeWriter{w: s}
			fmt.Fprintf(&e, "%%!%c(PANIC=SafeFormatter method: %v)", verb, p)
		}
	}()
	p := &printer{}
	p.escapeState = makeEscapeState(s, &p.buf)
	r.printFn(p, verb)
	_, _ = s.Write(p.buf.Bytes())
}

// passthrough passes a pre-formatted string through.
type passthrough struct{ arg []byte }

// Format implements fmt.Formatter.
func (p *passthrough) Format(s fmt.State, _ rune) {
	_, _ = s.Write(p.arg)
}

// escapeArg wraps an arbitrary value and ensures that any occurrence
// of the redaction markers in its representation are escaped.
//
// The result of printing out the value is enclosed within markers or
// not depending on the value of the enclose bool.
type escapeArg struct {
	arg     interface{}
	enclose bool
}

func (r *escapeArg) Format(s fmt.State, verb rune) {
	switch t := r.arg.(type) {
	case fmt.Formatter:
		// This is a special case from the default case below, which
		// allows a shortcut through the layers of the fmt package.
		p := &escapeState{
			State: s,
			w: escapeWriter{
				w:       s,
				enclose: r.enclose,
				strip:   r.enclose,
			}}
		defer func() {
			if recovered := recover(); recovered != nil {
				fmt.Fprintf(p, "%%!%c(PANIC=Format method: %v)", verb, recovered)
			}
		}()
		t.Format(p, verb)

	default:
		// TODO(knz): It would be possible to implement struct formatting
		// with conditional redaction based on field tag annotations here.
		p := &escapeWriter{w: s, enclose: r.enclose, strip: r.enclose}
		reproducePrintf(p, s, verb, r.arg)
	}
}

// printerfn is a helper struct for use by Sprintfn.
type printerfn struct {
	fn func(SafePrinter)
}

// SafeFormat implements the SafeFormatter interface.
func (p printerfn) SafeFormat(w SafePrinter, _ rune) {
	p.fn(w)
}

// redactErrorFn can be injected from an error library
// to render error objects safely.
var redactErrorFn func(err error, p SafePrinter, verb rune)

// RegisterRedactErrorFn registers an error redaction function for use
// during automatic redaction by this package.
// Provided e.g. by cockroachdb/errors.
func RegisterRedactErrorFn(fn func(err error, p SafePrinter, verb rune)) {
	redactErrorFn = fn
}
