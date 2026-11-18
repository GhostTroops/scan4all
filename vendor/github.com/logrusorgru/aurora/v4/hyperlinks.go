//
// Copyright (c) 2016-2022 The Aurora Authors. All rights reserved.
// This program is free software. It comes without any warranty,
// to the extent permitted by applicable law. You can redistribute
// it and/or modify it under the terms of the Unlicense. See LICENSE
// file for more details or see below.
//

//
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
//

package aurora

import (
	"fmt"
	"io"
)

const (
	linkStartEsc  = "\033]8;"
	linkMiddleEsc = "\033\\"
	linkEndEsc    = linkStartEsc + ";" + linkMiddleEsc
)

// Hyperlinks related constants
const (
	HyperlinkIDKey = "id" // hyperlink id parameter key
)

// The HyperlinkParam represents a hyperlink parameter.
type HyperlinkParam struct {
	Key   string // parameter name
	Value string // parameter value
}

func (hp HyperlinkParam) stringLen() int {
	return len(hp.Key) + 1 + len(hp.Value)
}

// String represents the HyperlinkParam as string, e.g. in key=value form.
func (hp HyperlinkParam) String() string {
	return hp.Key + "=" + hp.Value
}

// IsValidHyperlinkTarget returns true if the target contains symbols only
// in 32-126 ASCII range. All symbols outside this range should be URL-escaped.
func IsValidHyperlinkTarget(target string) (valid bool) {
	// we can walk over bytes, without Unicode runes decoding
	for i := 0; i < len(target); i++ {
		if target[i] < 32 || 126 < target[i] {
			return // false, should be URL-escaped
		}
	}
	return true
}

// range over bytes (not Unicode runes) and check
func containsAny(in string, any ...byte) (contains bool) {
	for i := 0; i < len(in); i++ {
		for _, b := range any {
			if in[i] == b {
				return true
			}
		}
	}
	return // false
}

// IsValidHyperlinkParam returns true for given string, if the string
// is valid hyperlink target (see IsValidHyperlinkTarget) and doesn't
// contains ':', ';' and '='.
func IsValidHyperlinkParam(param string) (valid bool) {
	return IsValidHyperlinkTarget(param) && !containsAny(param, ':', ';', '=')
}

// HyperlinkID returns list of HyperlinkParams that contains only id parameter
// with given value of the id parameter.
func HyperlinkID(id string) HyperlinkParam {
	return HyperlinkParam{
		Key:   HyperlinkIDKey,
		Value: id,
	}
}

type hyperlink struct {
	target string           // hyperlink target
	params []HyperlinkParam // hyperlink parameters
}

func (h *hyperlink) isExists() (ok bool) {
	if h == nil {
		return // does not exist
	}
	return h.target != ""
}

func (h *hyperlink) stringParamsLen() (ln int) {
	for i, p := range h.params {
		if i > 0 {
			ln++ // + colon separator
		}
		ln += p.stringLen()
	}
	return
}

func (h *hyperlink) headLen() int {
	return len(linkStartEsc) +
		h.stringParamsLen() +
		len(";") +
		len(h.target) +
		+len(linkMiddleEsc)
}

func (h *hyperlink) headBytes() (t []byte) {
	t = make([]byte, 0, h.headLen())

	t = append(t, linkStartEsc...)
	for i, param := range h.params {
		if i > 0 {
			t = append(t, ':')
		}
		t = append(t, param.Key...)
		t = append(t, '=')
		t = append(t, param.Value...)
	}
	t = append(t, ';')
	t = append(t, h.target...)
	t = append(t, linkMiddleEsc...)
	return
}

func (h *hyperlink) tailLen() int {
	return len(linkEndEsc)
}

func (h *hyperlink) tailBytes() []byte {
	return []byte(linkEndEsc)
}

func (h *hyperlink) writeHead(w io.Writer) {
	if h == nil || h.target == "" {
		return
	}
	w.Write(h.headBytes()) //nolint
}

func (h *hyperlink) writeTail(w io.Writer) {
	if h == nil || h.target == "" {
		return
	}
	w.Write(h.tailBytes()) //nolint
}

func shouldEscape(c byte) bool {
	return c < 32 || 126 < c
}

func isHex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// HyperlinkEscape escapes all symbols of given string out of [32; 126] range
// using URL-encoding. Used to escape a hyperlink target.
func HyperlinkEscape(s string) string {

	var hexCount int
	for i := 0; i < len(s); i++ {
		if shouldEscape(s[i]) {
			hexCount++
		}
	}

	if hexCount == 0 {
		return s
	}

	const upperhex = "0123456789ABCDEF"

	var (
		t = make([]byte, len(s)+2*hexCount)
		j int
	)

	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = upperhex[c>>4]
			t[j+2] = upperhex[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}

	return string(t)
}

// HyperlinkUnescape reverts a string escaped by the HyperlinkEscape.
func HyperlinkUnescape(s string) (raw string, err error) {

	var n int
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			n++
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[:3]
				}
				return "", fmt.Errorf("invalid URL-escape sequence: %q", s)
			}
			i += 3
		default:
			i++
		}
	}

	if n == 0 {
		return s, nil
	}

	var t = make([]byte, 0, len(s)-2*n)

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			t = append(t, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			t = append(t, s[i])
		}
	}

	return string(t), nil
}
