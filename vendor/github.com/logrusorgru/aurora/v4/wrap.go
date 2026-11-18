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

// DefaultColorizer is global colorizer that used for package root color
// methods.
var DefaultColorizer = New(WithColors(true), WithHyperlinks(true))

// Colorize wraps given value into Value with given colors. For example
//
//	var s = Colorize("some", BlueFg|GreenBg|BoldFm)
//
// returns a Value with blue foreground, green background and bold. Unlike
// functions like Red/BgBlue/Bold etc. This function clears all previous colors
// and formats. Thus
//
//	var s = Colorize(Red("some"), BgBlue)
//
// clears red color from value.
func Colorize(arg interface{}, color Color) Value {
	return DefaultColorizer.Colorize(arg, color)
}

// Reset wraps given argument returning Value without formats, colors and links.
func Reset(arg interface{}) Value {
	return DefaultColorizer.Reset(arg)
}

// Clear wraps given argument returning Value without formats and colors. But
// preserving links.
func Clear(arg interface{}) Value {
	return DefaultColorizer.Clear(arg)
}

//
// Formats
//

// Bold or increased intensity (1).
func Bold(arg interface{}) Value {
	return DefaultColorizer.Bold(arg)
}

// Faint decreases intensity (2). The Faint rejects the Bold.
func Faint(arg interface{}) Value {
	return DefaultColorizer.Faint(arg)
}

// DoublyUnderline or Bold off, double-underline per ECMA-48 (21).
func DoublyUnderline(arg interface{}) Value {
	return DefaultColorizer.DoublyUnderline(arg)
}

// Fraktur is rarely supported (20).
func Fraktur(arg interface{}) Value {
	return DefaultColorizer.Fraktur(arg)
}

// Italic is not widely supported, sometimes treated as inverse (3).
func Italic(arg interface{}) Value {
	return DefaultColorizer.Italic(arg)
}

// Underline (4).
func Underline(arg interface{}) Value {
	return DefaultColorizer.Underline(arg)
}

// SlowBlink makes text blink less than 150 per minute (5).
func SlowBlink(arg interface{}) Value {
	return DefaultColorizer.SlowBlink(arg)
}

// RapidBlink makes text blink 150+ per minute. It is not widely supported (6).
func RapidBlink(arg interface{}) Value {
	return DefaultColorizer.RapidBlink(arg)
}

// Blink is alias for the SlowBlink.
func Blink(arg interface{}) Value {
	return DefaultColorizer.Blink(arg)
}

// Reverse video, swap foreground and background colors (7).
func Reverse(arg interface{}) Value {
	return DefaultColorizer.Reverse(arg)
}

// Inverse is alias for the Reverse
func Inverse(arg interface{}) Value {
	return DefaultColorizer.Inverse(arg)
}

// Conceal hides text, preserving an ability to select the text and copy it. It
// is not widely supported (8).
func Conceal(arg interface{}) Value {
	return DefaultColorizer.Conceal(arg)
}

// Hidden is alias for the Conceal
func Hidden(arg interface{}) Value {
	return DefaultColorizer.Hidden(arg)
}

// CrossedOut makes characters legible, but marked for deletion (9).
func CrossedOut(arg interface{}) Value {
	return DefaultColorizer.CrossedOut(arg)
}

// StrikeThrough is alias for the CrossedOut.
func StrikeThrough(arg interface{}) Value {
	return DefaultColorizer.StrikeThrough(arg)
}

// Framed (51).
func Framed(arg interface{}) Value {
	return DefaultColorizer.Framed(arg)
}

// Encircled (52).
func Encircled(arg interface{}) Value {
	return DefaultColorizer.Encircled(arg)
}

// Overlined (53).
func Overlined(arg interface{}) Value {
	return DefaultColorizer.Overlined(arg)
}

//
// Foreground colors
//
//

// Black foreground color (30)
func Black(arg interface{}) Value {
	return DefaultColorizer.Black(arg)
}

// Red foreground color (31)
func Red(arg interface{}) Value {
	return DefaultColorizer.Red(arg)
}

// Green foreground color (32)
func Green(arg interface{}) Value {
	return DefaultColorizer.Green(arg)
}

// Yellow foreground color (33)
func Yellow(arg interface{}) Value {
	return DefaultColorizer.Yellow(arg)
}

// Blue foreground color (34)
func Blue(arg interface{}) Value {
	return DefaultColorizer.Blue(arg)
}

// Magenta foreground color (35)
func Magenta(arg interface{}) Value {
	return DefaultColorizer.Magenta(arg)
}

// Cyan foreground color (36)
func Cyan(arg interface{}) Value {
	return DefaultColorizer.Cyan(arg)
}

// White foreground color (37)
func White(arg interface{}) Value {
	return DefaultColorizer.White(arg)
}

//
// Bright foreground colors
//

// BrightBlack foreground color (90)
func BrightBlack(arg interface{}) Value {
	return DefaultColorizer.BrightBlack(arg)
}

// BrightRed foreground color (91)
func BrightRed(arg interface{}) Value {
	return DefaultColorizer.BrightRed(arg)
}

// BrightGreen foreground color (92)
func BrightGreen(arg interface{}) Value {
	return DefaultColorizer.BrightGreen(arg)
}

// BrightYellow foreground color (93)
func BrightYellow(arg interface{}) Value {
	return DefaultColorizer.BrightYellow(arg)
}

// BrightBlue foreground color (94)
func BrightBlue(arg interface{}) Value {
	return DefaultColorizer.BrightBlue(arg)
}

// BrightMagenta foreground color (95)
func BrightMagenta(arg interface{}) Value {
	return DefaultColorizer.BrightMagenta(arg)
}

// BrightCyan foreground color (96)
func BrightCyan(arg interface{}) Value {
	return DefaultColorizer.BrightCyan(arg)
}

// BrightWhite foreground color (97)
func BrightWhite(arg interface{}) Value {
	return DefaultColorizer.BrightWhite(arg)
}

//
// Other
//

// Index of pre-defined 8-bit foreground color from 0 to 255 (38;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 30–37 m)
//	  8- 15:  high intensity colors (as in ESC [ 90–97 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
func Index(n ColorIndex, arg interface{}) Value {
	return DefaultColorizer.Index(n, arg)
}

// Gray from 0 to 24.
func Gray(n GrayIndex, arg interface{}) Value {
	return DefaultColorizer.Gray(n, arg)
}

//
// Background colors
//
//

// BgBlack background color (40)
func BgBlack(arg interface{}) Value {
	return DefaultColorizer.BgBlack(arg)
}

// BgRed background color (41)
func BgRed(arg interface{}) Value {
	return DefaultColorizer.BgRed(arg)
}

// BgGreen background color (42)
func BgGreen(arg interface{}) Value {
	return DefaultColorizer.BgGreen(arg)
}

// BgYellow background color (43)
func BgYellow(arg interface{}) Value {
	return DefaultColorizer.BgYellow(arg)
}

// BgBlue background color (44)
func BgBlue(arg interface{}) Value {
	return DefaultColorizer.BgBlue(arg)
}

// BgMagenta background color (45)
func BgMagenta(arg interface{}) Value {
	return DefaultColorizer.BgMagenta(arg)
}

// BgCyan background color (46)
func BgCyan(arg interface{}) Value {
	return DefaultColorizer.BgCyan(arg)
}

// BgWhite background color (47)
func BgWhite(arg interface{}) Value {
	return DefaultColorizer.BgWhite(arg)
}

//
// Bright background colors
//

// BgBrightBlack background color (100)
func BgBrightBlack(arg interface{}) Value {
	return DefaultColorizer.BgBrightBlack(arg)
}

// BgBrightRed background color (101)
func BgBrightRed(arg interface{}) Value {
	return DefaultColorizer.BgBrightRed(arg)
}

// BgBrightGreen background color (102)
func BgBrightGreen(arg interface{}) Value {
	return DefaultColorizer.BgBrightGreen(arg)
}

// BgBrightYellow background color (103)
func BgBrightYellow(arg interface{}) Value {
	return DefaultColorizer.BgBrightYellow(arg)
}

// BgBrightBlue background color (104)
func BgBrightBlue(arg interface{}) Value {
	return DefaultColorizer.BgBrightBlue(arg)
}

// BgBrightMagenta background color (105)
func BgBrightMagenta(arg interface{}) Value {
	return DefaultColorizer.BgBrightMagenta(arg)
}

// BgBrightCyan background color (106)
func BgBrightCyan(arg interface{}) Value {
	return DefaultColorizer.BgBrightCyan(arg)
}

// BgBrightWhite background color (107)
func BgBrightWhite(arg interface{}) Value {
	return DefaultColorizer.BgBrightWhite(arg)
}

//
// Other
//

// BgIndex of 8-bit pre-defined background color from 0 to 255 (48;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 40–47 m)
//	  8- 15:  high intensity colors (as in ESC [100–107 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
func BgIndex(n ColorIndex, arg interface{}) Value {
	return DefaultColorizer.BgIndex(n, arg)
}

// BgGray from 0 to 24.
func BgGray(n GrayIndex, arg interface{}) Value {
	return DefaultColorizer.BgGray(n, arg)
}

//
// Hyperlinks feature
//

// Hyperlink with given target and parameters. If hyperlinks feature is
// disabled, then the 'arg' argument dropped and the 'target' used instead
// inheriting all colors and format from the 'arg' (if it's a Colored).
//
// See https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
// for details about the hyperlinks feature.
//
// The Hyperlink doesn't escape the target and the params. They should be
// checked and escaped before.
//
// See also HyperlinkID function.
//
// For a simple example
//
//	au.Hyperlink("Example", "http://example.com")
//
// and an example with ID
//
//	au.Hyperlink("Example", "http://example.com", aurora.HyperlinkID("10"))
func Hyperlink(arg interface{}, target string, params ...HyperlinkParam) Value {
	return DefaultColorizer.Hyperlink(arg, target, params...)
}

// HyperlinkTarget of the argument if it's a Value.
func HyperlinkTarget(arg interface{}) (target string) {
	return DefaultColorizer.HyperlinkTarget(arg)
}

// HyperlinkParams of the argument if it's a Value.
func HyperlinkParams(arg interface{}) (params []HyperlinkParam) {
	return DefaultColorizer.HyperlinkParams(arg)
}

// Sprintf allows to use Value as format. For example
//
//	var v = Sprintf(Red("total: +3.5f points"), Blue(3.14))
//
// In this case "total:" and "points" will be red, but
// 3.14 will be blue. But, in another example
//
//	var v = Sprintf(Red("total: +3.5f points"), 3.14)
//
// full string will be red. And no way to clear 3.14 to default format and
// color.
//
// It applies own configurations to all given Values.
func Sprintf(format interface{}, args ...interface{}) string {
	return DefaultColorizer.Sprintf(format, args...)
}
