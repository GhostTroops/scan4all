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

package fmt

// printArg overrides the original implementation by redirecting the
// call to a substitute function in the printer, if available.
func (p *pp) printArg(a interface{}, verb rune) {
	if p.printArgSubstituteFn != nil {
		p.substituteState = p.printArgSubstituteFn(p, a, verb)
	} else {
		p.printArgOrig(a, verb)
	}
}

// InternalPrinter exposes pp to the redact package.
type InternalPrinter = pp

// InternalBuffer exposes buffer to the redact package.
type InternalBuffer = buffer

// NewInternalPrinter exposes pp allocation to the redact package.
func NewInternalPrinter() *InternalPrinter { return newPrinter() }

// SetHook connects an outer printer to the inner printer.
func SetHook(
	p *InternalPrinter, fn func(p *InternalPrinter, arg interface{}, verb rune) (newState int),
) {
	p.printArgSubstituteFn = fn
}

// Free exposes pp deallocation to the redact package.
func Free(p *InternalPrinter) {
	p.substituteState = 0
	p.printArgSubstituteFn = nil
	p.free()
}

// Buf exposes the string buffer to the redact package.
func Buf(p *InternalPrinter) []byte { return []byte(p.buf) }

// GetState exposes the state to the redact package.
func GetState(p *InternalPrinter) int {
	return p.substituteState
}

// SetState exposes the string buffer to the redact package.
func SetState(p *InternalPrinter, b []byte) {
	p.buf = buffer(b)
	p.substituteState = len(p.buf)
}

// Append adds bytes to the buffer.
func Append(p *InternalPrinter, b []byte) { p.buf.write(b) }

// PrintArg exposes the printArgOrig() method to the redact package.
func PrintArg(p *InternalPrinter, a interface{}, verb rune) { p.printArgOrig(a, verb) }

// DoPrint exposes the doPrint() method to the redact package.
func DoPrint(p *InternalPrinter, a []interface{}) { p.doPrint(a) }

// DoPrintf exposes the doPrintf() method to the redact package.
func DoPrintf(p *InternalPrinter, format string, a []interface{}) { p.doPrintf(format, a) }

// SetCollectError enables wrapped error collection.
func SetCollectError(p *InternalPrinter) { p.wrapErrs = true }

// CollectingError exposes wrapped error collection.
func CollectingError(p *InternalPrinter) bool { return p.wrapErrs }

// WrappedError retrieves the wrapped error if found.
func WrappedError(p *InternalPrinter) error { return p.wrappedErr }
