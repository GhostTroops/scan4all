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
	"strconv"
	"unicode/utf8"
)

// compile-time check
var (
	_ fmt.Stringer  = Value{}
	_ fmt.Formatter = Value{}
	_ Colored       = Value{}
)

func coloredFormat(color Color, s fmt.State, verb rune) string {

	// it's enough for many cases (%-+020.10f)
	// %          - 1
	// availFlags - 3 (5)
	// width      - 2
	// prec       - 3 (.23)
	// verb       - 1
	// --------------
	//             10
	// +
	// \033[                            5
	// 0;1;3;4;5;7;8;9;20;21;51;52;53  30
	// 38;5;216                         8
	// 48;5;216                         8
	// m                                1
	// +
	// \033[0m                          7
	//
	// x2 (possible tail color)
	//
	// 10 + 59 * 2 = 128

	var format = make([]byte, 0, 128)

	if color != 0 {
		format = append(format, esc...)
		format = color.appendNos(format, false)
		format = append(format, 'm')
	}

	format = append(format, '%')

	var f byte
	for i := 0; i < len(availFlags); i++ {
		if f = availFlags[i]; s.Flag(int(f)) {
			format = append(format, f)
		}
	}

	var (
		width, prec int
		ok          bool
	)
	if width, ok = s.Width(); ok {
		format = strconv.AppendInt(format, int64(width), 10)
	}

	if prec, ok = s.Precision(); ok {
		format = append(format, '.')
		format = strconv.AppendInt(format, int64(prec), 10)
	}

	if verb > utf8.RuneSelf {
		format = append(format, string(verb)...)
	} else {
		format = append(format, byte(verb))
	}

	if color != 0 {
		format = append(format, clear...) // just clear
	}

	return string(format)
}

type colorConfig uint64

const (
	colorPin      colorConfig = 1 << 32
	hyperlinksPin colorConfig = 1 << 33
)

func (cc colorConfig) colorsEnabled() bool {
	return cc&colorPin != 0
}

func (cc colorConfig) hyperlinksEnbaled() bool {
	return cc&hyperlinksPin != 0
}

func (cc colorConfig) color() Color {
	if cc.colorsEnabled() {
		return Color(uint32(cc)) // lower 32 bits only
	}
	return 0 // even if a color set
}

func (cc colorConfig) resetColor() colorConfig {
	return cc & (colorPin | hyperlinksPin)
}

// A Value represents any printable value
// with or without colors, formats and a link.
type Value struct {
	value     interface{} // value as is
	cc        colorConfig // color & config
	hyperlink *hyperlink  // hyperlink target and parameters
}

// String implements standard fmt.Stringer interface.
func (v Value) String() string {
	var (
		t     []byte
		val   = fmt.Sprint(v.value)
		color = v.cc.color()
	)

	if v.cc.hyperlinksEnbaled() && v.hyperlink.isExists() {
		var (
			ln  = len(val)
			nos string
		)
		// calculate length
		ln += v.hyperlink.headLen()
		if color != 0 {
			ln += len(esc)
			nos = color.Nos(false)
			ln += len(nos) + len("m")
			ln += len(clear)
		}
		ln += v.hyperlink.tailLen()
		// fill
		t = make([]byte, 0, ln)
		t = append(t, v.hyperlink.headBytes()...)
		if color != 0 {
			t = append(t, esc...)
			t = append(t, nos...)
			t = append(t, 'm')
			t = append(t, val...)
			t = append(t, clear...)
		} else {
			t = append(t, val...)
		}
		t = append(t, v.hyperlink.tailBytes()...)
		return string(t)
	}

	// no links, only colors & formats
	if color != 0 {
		return esc + color.Nos(false) + "m" + val + clear
	}

	// no links, no colors, no formats, just the value
	return val
}

// Color returns colors and formats of the Value.
func (v Value) Color() Color {
	return v.cc.color()
}

// Reset colors, formats and links.
func (v Value) Reset() Value {
	v.cc, v.hyperlink = v.cc.resetColor(), nil
	return v
}

// Clear colors and formats, preserving links.
func (v Value) Clear() Value {
	v.cc = v.cc.resetColor()
	return v
}

// Value returns value's value (welcome to the tautology club)
func (v Value) Value() interface{} {
	return v.value
}

// Format implements standard fmt.Formatter interface.
func (v Value) Format(s fmt.State, verb rune) {
	if !v.cc.hyperlinksEnbaled() {
		fmt.Fprintf(s, coloredFormat(v.Color(), s, verb), v.value)
		return
	}
	v.hyperlink.writeHead(s)
	fmt.Fprintf(s, coloredFormat(v.Color(), s, verb), v.value)
	v.hyperlink.writeTail(s)
}

// Formats
//
// Bold or increased intensity (1).
func (v Value) Bold() Value {
	v.cc = colorConfig(v.cc.color().Bold()) | v.cc.resetColor()
	return v
}

// Faint, decreased intensity, reset the Bold (2).
func (v Value) Faint() Value {
	v.cc = colorConfig(v.cc.color().Faint()) | v.cc.resetColor()
	return v
}

// DoublyUnderline or Bold off, double-underline per ECMA-48 (21). It depends.
func (v Value) DoublyUnderline() Value {
	v.cc = colorConfig(v.cc.color().DoublyUnderline()) | v.cc.resetColor()
	return v
}

// Fraktur, rarely supported (20).
func (v Value) Fraktur() Value {
	v.cc = colorConfig(v.cc.color().Fraktur()) | v.cc.resetColor()
	return v
}

// Italic, not widely supported, sometimes treated as inverse (3).
func (v Value) Italic() Value {
	v.cc = colorConfig(v.cc.color().Italic()) | v.cc.resetColor()
	return v
}

// Underline (4).
func (v Value) Underline() Value {
	v.cc = colorConfig(v.cc.color().Underline()) | v.cc.resetColor()
	return v
}

// SlowBlink, blinking less than 150 per minute (5).
func (v Value) SlowBlink() Value {
	v.cc = colorConfig(v.cc.color().SlowBlink()) | v.cc.resetColor()
	return v
}

// RapidBlink, blinking 150+ per minute, not widely supported (6).
func (v Value) RapidBlink() Value {
	v.cc = colorConfig(v.cc.color().RapidBlink()) | v.cc.resetColor()
	return v
}

// Blink is alias for the SlowBlink.
func (v Value) Blink() Value {
	return v.SlowBlink()
}

// Reverse video, swap foreground and background colors (7).
func (v Value) Reverse() Value {
	v.cc = colorConfig(v.cc.color().Reverse()) | v.cc.resetColor()
	return v
}

// Inverse is alias for the Reverse.
func (v Value) Inverse() Value {
	return v.Reverse()
}

// Conceal, hidden, not widely supported (8).
func (v Value) Conceal() Value {
	v.cc = colorConfig(v.cc.color().Conceal()) | v.cc.resetColor()
	return v
}

// Hidden is alias for the Conceal.
func (v Value) Hidden() Value {
	return v.Conceal()
}

// CrossedOut, characters legible, but marked for deletion (9).
func (v Value) CrossedOut() Value {
	v.cc = colorConfig(v.cc.color().CrossedOut()) | v.cc.resetColor()
	return v
}

// StrikeThrough is alias for the CrossedOut.
func (v Value) StrikeThrough() Value {
	return v.CrossedOut()
}

// Framed (51).
func (v Value) Framed() Value {
	v.cc = colorConfig(v.cc.color().Framed()) | v.cc.resetColor()
	return v
}

// Encircled (52).
func (v Value) Encircled() Value {
	v.cc = colorConfig(v.cc.color().Encircled()) | v.cc.resetColor()
	return v
}

// Overlined (53).
func (v Value) Overlined() Value {
	v.cc = colorConfig(v.cc.color().Overlined()) | v.cc.resetColor()
	return v
}

// Foreground colors.
//
// Black foreground color (30).
func (v Value) Black() Value {
	v.cc = colorConfig(v.cc.color().Black()) | v.cc.resetColor()
	return v
}

// Red foreground color (31).
func (v Value) Red() Value {
	v.cc = colorConfig(v.cc.color().Red()) | v.cc.resetColor()
	return v
}

// Green foreground color (32).
func (v Value) Green() Value {
	v.cc = colorConfig(v.cc.color().Green()) | v.cc.resetColor()
	return v
}

// Yellow foreground color (33).
func (v Value) Yellow() Value {
	v.cc = colorConfig(v.cc.color().Yellow()) | v.cc.resetColor()
	return v
}

// Blue foreground color (34).
func (v Value) Blue() Value {
	v.cc = colorConfig(v.cc.color().Blue()) | v.cc.resetColor()
	return v
}

// Magenta foreground color (35).
func (v Value) Magenta() Value {
	v.cc = colorConfig(v.cc.color().Magenta()) | v.cc.resetColor()
	return v
}

// Cyan foreground color (36).
func (v Value) Cyan() Value {
	v.cc = colorConfig(v.cc.color().Cyan()) | v.cc.resetColor()
	return v
}

// White foreground color (37).
func (v Value) White() Value {
	v.cc = colorConfig(v.cc.color().White()) | v.cc.resetColor()
	return v
}

// Bright foreground colors.
//
// BrightBlack foreground color (90).
func (v Value) BrightBlack() Value {
	v.cc = colorConfig(v.cc.color().BrightBlack()) | v.cc.resetColor()
	return v
}

// BrightRed foreground color (91).
func (v Value) BrightRed() Value {
	v.cc = colorConfig(v.cc.color().BrightRed()) | v.cc.resetColor()
	return v
}

// BrightGreen foreground color (92).
func (v Value) BrightGreen() Value {
	v.cc = colorConfig(v.cc.color().BrightGreen()) | v.cc.resetColor()
	return v
}

// BrightYellow foreground color (93).
func (v Value) BrightYellow() Value {
	v.cc = colorConfig(v.cc.color().BrightYellow()) | v.cc.resetColor()
	return v
}

// BrightBlue foreground color (94).
func (v Value) BrightBlue() Value {
	v.cc = colorConfig(v.cc.color().BrightBlue()) | v.cc.resetColor()
	return v
}

// BrightMagenta foreground color (95).
func (v Value) BrightMagenta() Value {
	v.cc = colorConfig(v.cc.color().BrightMagenta()) | v.cc.resetColor()
	return v
}

// BrightCyan foreground color (96).
func (v Value) BrightCyan() Value {
	v.cc = colorConfig(v.cc.color().BrightCyan()) | v.cc.resetColor()
	return v
}

// BrightWhite foreground color (97).
func (v Value) BrightWhite() Value {
	v.cc = colorConfig(v.cc.color().BrightWhite()) | v.cc.resetColor()
	return v
}

// Other colors.
//
// Index of pre-defined 8-bit foreground color from 0 to 255 (38;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 30–37 m)
//	  8- 15:  high intensity colors (as in ESC [ 90–97 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
func (v Value) Index(n ColorIndex) Value {
	v.cc = colorConfig(v.cc.color().Index(n)) | v.cc.resetColor()
	return v
}

// Gray from 0 to 24.
func (v Value) Gray(n GrayIndex) Value {
	v.cc = colorConfig(v.cc.color().Gray(n)) | v.cc.resetColor()
	return v
}

// Background colors
//
// BgBlack background color (40).
func (v Value) BgBlack() Value {
	v.cc = colorConfig(v.cc.color().BgBlack()) | v.cc.resetColor()
	return v
}

// BgRed background color (41).
func (v Value) BgRed() Value {
	v.cc = colorConfig(v.cc.color().BgRed()) | v.cc.resetColor()
	return v
}

// BgGreen background color (42).
func (v Value) BgGreen() Value {
	v.cc = colorConfig(v.cc.color().BgGreen()) | v.cc.resetColor()
	return v
}

// BgYellow background color (43).
func (v Value) BgYellow() Value {
	v.cc = colorConfig(v.cc.color().BgYellow()) | v.cc.resetColor()
	return v
}

// BgBlue background color (44).
func (v Value) BgBlue() Value {
	v.cc = colorConfig(v.cc.color().BgBlue()) | v.cc.resetColor()
	return v
}

// BgMagenta background color (45).
func (v Value) BgMagenta() Value {
	v.cc = colorConfig(v.cc.color().BgMagenta()) | v.cc.resetColor()
	return v
}

// BgCyan background color (46).
func (v Value) BgCyan() Value {
	v.cc = colorConfig(v.cc.color().BgCyan()) | v.cc.resetColor()
	return v
}

// BgWhite background color (47).
func (v Value) BgWhite() Value {
	v.cc = colorConfig(v.cc.color().BgWhite()) | v.cc.resetColor()
	return v
}

// Bright background colors.
//
// BgBrightBlack background color (100).
func (v Value) BgBrightBlack() Value {
	v.cc = colorConfig(v.cc.color().BgBrightBlack()) | v.cc.resetColor()
	return v
}

// BgBrightRed background color (101).
func (v Value) BgBrightRed() Value {
	v.cc = colorConfig(v.cc.color().BgBrightRed()) | v.cc.resetColor()
	return v
}

// BgBrightGreen background color (102).
func (v Value) BgBrightGreen() Value {
	v.cc = colorConfig(v.cc.color().BgBrightGreen()) | v.cc.resetColor()
	return v
}

// BgBrightYellow background color (103).
func (v Value) BgBrightYellow() Value {
	v.cc = colorConfig(v.cc.color().BgBrightYellow()) | v.cc.resetColor()
	return v
}

// BgBrightBlue background color (104).
func (v Value) BgBrightBlue() Value {
	v.cc = colorConfig(v.cc.color().BgBrightBlue()) | v.cc.resetColor()
	return v
}

// BgBrightMagenta background color (105).
func (v Value) BgBrightMagenta() Value {
	v.cc = colorConfig(v.cc.color().BgBrightMagenta()) | v.cc.resetColor()
	return v
}

// BgBrightCyan background color (106).
func (v Value) BgBrightCyan() Value {
	v.cc = colorConfig(v.cc.color().BgBrightCyan()) | v.cc.resetColor()
	return v
}

// BgBrightWhite background color (107).
func (v Value) BgBrightWhite() Value {
	v.cc = colorConfig(v.cc.color().BgBrightWhite()) | v.cc.resetColor()
	return v
}

// Other background colors.
//
// BgIndex of 8-bit pre-defined background color from 0 to 255 (48;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 40–47 m)
//	  8- 15:  high intensity colors (as in ESC [100–107 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
func (v Value) BgIndex(n ColorIndex) Value {
	v.cc = colorConfig(v.cc.color().BgIndex(n)) | v.cc.resetColor()
	return v
}

// BgGray from 0 to 24.
func (v Value) BgGray(n GrayIndex) Value {
	v.cc = colorConfig(v.cc.color().BgGray(n)) | v.cc.resetColor()
	return v
}

// Special colorization method.
//
// Colorize removes existing colors and formats of the argument and applies
// given.
func (v Value) Colorize(color Color) Value {
	v.cc = colorConfig(color) | v.cc.resetColor()
	return v
}

// Hyperlinks feature
//
// Hyperlink with given target and parameters. If hyperlinks feature is
// disabled, then the 'arg' argument dropped and the 'target' used instead,
// inheriting all colors and format from the 'arg' (if it's a Colored).
//
// See https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
// for details about the hyperlinks feature.
//
// The Hyperlink doesn't escape the target and the parameters. They should be
// checked and escaped before. See HyperlinkEscape function.
//
// See also HyperlinkID function.
//
// For a simple example
//
//	val.Hyperlink("http://example.com")
//
// and an example with ID
//
//	val.Hyperlink("http://example.com", aurora.HyperlinkID("10"))
//
// Successive calls replace previously set target and parameters.
func (v Value) Hyperlink(target string, params ...HyperlinkParam) Value {
	if !v.cc.hyperlinksEnbaled() {
		v.value = target // drop value, use the target
		v.hyperlink = &hyperlink{
			target: target, // keep for the HyperlinkTarget method
		}
		return v
	}
	if v.hyperlink == nil {
		v.hyperlink = new(hyperlink)
	}
	v.hyperlink.target = target
	v.hyperlink.params = params
	return v
}

// HyperlinkTarget if any.
func (v Value) HyperlinkTarget() (target string) {
	if v.hyperlink != nil {
		return v.hyperlink.target
	}
	return // nothing
}

// HyperlinkParams if any.
func (v Value) HyperlinkParams() (params []HyperlinkParam) {
	if v.hyperlink != nil {
		return v.hyperlink.params
	}
	return // nil
}
