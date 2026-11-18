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

// A Color type is a color. It can contain
// one background color, one foreground color
// and a format, including ideogram related
// formats.
type Color uint

/*

	Developer note.

	The uint type is architecture depended and can be
	represented as int32 or int64.

	Thus, we can use 32-bits only to be fast and
	cross-platform.

	All supported formats requires 14 bits. It is
	first 14 bits.

	A foreground color requires 8 bit + 1 bit (presence flag).
	And the same for background color.

	The Color representations

	[ bg 8 bit ] [fg 8 bit ] [ fg/bg 2 bits ] [ fm 14 bits ]

	https://play.golang.org/p/fq2zcNstFoF

*/

// Special formats
const (
	BoldFm       Color = 1 << iota // 1
	FaintFm                        // 2
	ItalicFm                       // 3
	UnderlineFm                    // 4
	SlowBlinkFm                    // 5
	RapidBlinkFm                   // 6
	ReverseFm                      // 7
	ConcealFm                      // 8
	CrossedOutFm                   // 9

	FrakturFm         // 20
	DoublyUnderlineFm // 21 or bold off for some systems

	FramedFm    // 51
	EncircledFm // 52
	OverlinedFm // 53

	InverseFm       = ReverseFm    // alias to ReverseFm
	BlinkFm         = SlowBlinkFm  // alias to SlowBlinkFm
	HiddenFm        = ConcealFm    // alias to ConcealFm
	StrikeThroughFm = CrossedOutFm // alias to CrossedOutFm

	maskFm = BoldFm | FaintFm |
		ItalicFm | UnderlineFm |
		SlowBlinkFm | RapidBlinkFm |
		ReverseFm |
		ConcealFm | CrossedOutFm |

		FrakturFm | DoublyUnderlineFm |

		FramedFm | EncircledFm | OverlinedFm

	flagFg Color = 1 << 14 // presence flag (14th bit)
	flagBg Color = 1 << 15 // presence flag (15th bit)

	shiftFg = 16 // shift for foreground (starting from 16th bit)
	shiftBg = 24 // shift for background (starting from 24th bit)
)

// Foreground colors and related formats
const (

	// 8 bits

	// [  0;   7] - 30-37
	// [  8;  15] - 90-97 bright
	// [ 16; 231] - RGB
	// [232; 255] - grayscale

	BlackFg   Color = (iota << shiftFg) | flagFg // 30, 90
	RedFg                                        // 31, 91
	GreenFg                                      // 32, 92
	YellowFg                                     // 33, 93
	BlueFg                                       // 34, 94
	MagentaFg                                    // 35, 95
	CyanFg                                       // 36, 96
	WhiteFg                                      // 37, 97

	BrightFg Color = ((1 << 3) << shiftFg) | flagFg // -> 90

	// the BrightFg itself doesn't represent
	// a color, thus it has not flagFg

	// 5 bits

	//
	maskFg = (0xff << shiftFg) | flagFg
)

// Background colors and related formats
const (

	// 8 bits

	// [  0;   7] - 40-47
	// [  8;  15] - 100-107 bright
	// [ 16; 231] - RGB
	// [232; 255] - grayscale

	BlackBg   Color = (iota << shiftBg) | flagBg // 40, 100
	RedBg                                        // 41, 101
	GreenBg                                      // 42, 102
	YellowBg                                     // 43, 103
	BlueBg                                       // 44, 104
	MagentaBg                                    // 45, 105
	CyanBg                                       // 46, 106
	WhiteBg                                      // 47, 107

	BrightBg Color = ((1 << 3) << shiftBg) | flagBg // -> 100

	// the BrightBg itself doesn't represent
	// a color, thus it has not flagBg

	// 5 bits

	//
	maskBg = (0xff << shiftBg) | flagBg
)

const (
	availFlags = "-+# 0"
	esc        = "\033["
	clear      = esc + "0m"
)

// Nos returns string like 1;7;31;45. It
// may be an empty string for empty color.
// If the zero is true, then the string
// is prepended with 0;
func (c Color) Nos(zero bool) string {
	return string(c.appendNos(make([]byte, 0, 59), zero))
}

func appendCond(bs []byte, cond, semi bool, vals ...byte) []byte {
	if !cond {
		return bs
	}
	return appendSemi(bs, semi, vals...)
}

// if the semi is true, then prepend with semicolon
func appendSemi(bs []byte, semi bool, vals ...byte) []byte {
	if semi {
		bs = append(bs, ';')
	}
	return append(bs, vals...)
}

func itoa(t byte) string {
	var (
		a [3]byte
		j = 2
	)
	for i := 0; i < 3; i, j = i+1, j-1 {
		a[j] = '0' + t%10
		if t = t / 10; t == 0 {
			break
		}
	}
	return string(a[j:])
}

func (c Color) appendFg(bs []byte, zero bool) []byte {

	if zero || c&maskFm != 0 {
		bs = append(bs, ';')
	}

	// 0- 7 :  30-37
	// 8-15 :  90-97
	// > 15 : 38;5;val

	switch fg := (c & maskFg) >> shiftFg; {
	case fg <= 7:
		// '3' and the value itself
		bs = append(bs, '3', '0'+byte(fg))
	case fg <= 15:
		// '9' and the value itself
		bs = append(bs, '9', '0'+byte(fg&^0x08)) // clear bright flag
	default:
		bs = append(bs, '3', '8', ';', '5', ';')
		bs = append(bs, itoa(byte(fg))...)
	}
	return bs
}

func (c Color) appendBg(bs []byte, zero bool) []byte {

	if zero || c&(maskFm|maskFg) != 0 {
		bs = append(bs, ';')
	}

	// 0- 7 :  40- 47
	// 8-15 : 100-107
	// > 15 : 48;5;val

	switch fg := (c & maskBg) >> shiftBg; {
	case fg <= 7:
		// '3' and the value itself
		bs = append(bs, '4', '0'+byte(fg))
	case fg <= 15:
		// '1', '0' and the value itself
		bs = append(bs, '1', '0', '0'+byte(fg&^0x08)) // clear bright flag
	default:
		bs = append(bs, '4', '8', ';', '5', ';')
		bs = append(bs, itoa(byte(fg))...)
	}
	return bs
}

func (c Color) appendFm9(bs []byte, zero bool) []byte {

	bs = appendCond(bs, c&ItalicFm != 0,
		zero || c&(BoldFm|FaintFm) != 0,
		'3')
	bs = appendCond(bs, c&UnderlineFm != 0,
		zero || c&(BoldFm|FaintFm|ItalicFm) != 0,
		'4')
	// don't combine slow and rapid blink using only
	// on of them, preferring slow blink
	if c&SlowBlinkFm != 0 {
		bs = appendSemi(bs,
			zero || c&(BoldFm|FaintFm|ItalicFm|UnderlineFm) != 0,
			'5')
	} else if c&RapidBlinkFm != 0 {
		bs = appendSemi(bs,
			zero || c&(BoldFm|FaintFm|ItalicFm|UnderlineFm) != 0,
			'6')
	}

	// including 1-2
	const mask6i = BoldFm | FaintFm |
		ItalicFm | UnderlineFm |
		SlowBlinkFm | RapidBlinkFm

	bs = appendCond(bs, c&ReverseFm != 0,
		zero || c&(mask6i) != 0,
		'7')
	bs = appendCond(bs, c&ConcealFm != 0,
		zero || c&(mask6i|ReverseFm) != 0,
		'8')
	bs = appendCond(bs, c&CrossedOutFm != 0,
		zero || c&(mask6i|ReverseFm|ConcealFm) != 0,
		'9')

	return bs
}

// append 1;3;38;5;216 like string that represents ANSI
// color of the Color; the zero argument requires
// appending of '0' before to reset previous format
// and colors
func (c Color) appendNos(bs []byte, zero bool) []byte {

	if zero {
		bs = append(bs, '0') // reset previous
	}

	// formats
	//

	if c&maskFm != 0 {

		// 1-2

		// don't combine bold and faint using only on of them, preferring bold

		if c&BoldFm != 0 {
			bs = appendSemi(bs, zero, '1')
		} else if c&FaintFm != 0 {
			bs = appendSemi(bs, zero, '2')
		}

		// 3-9

		const mask9 = ItalicFm | UnderlineFm |
			SlowBlinkFm | RapidBlinkFm |
			ReverseFm | ConcealFm | CrossedOutFm

		if c&mask9 != 0 {
			bs = c.appendFm9(bs, zero)
		}

		// 20-21

		const (
			mask21 = FrakturFm | DoublyUnderlineFm
			mask9i = BoldFm | FaintFm | mask9
		)

		if c&mask21 != 0 {
			bs = appendCond(bs, c&FrakturFm != 0,
				zero || c&mask9i != 0,
				'2', '0')
			bs = appendCond(bs, c&DoublyUnderlineFm != 0,
				zero || c&(mask9i|FrakturFm) != 0,
				'2', '1')
		}

		// 50-53

		const (
			mask53  = FramedFm | EncircledFm | OverlinedFm
			mask21i = mask9i | mask21
		)

		if c&mask53 != 0 {
			bs = appendCond(bs, c&FramedFm != 0,
				zero || c&mask21i != 0,
				'5', '1')
			bs = appendCond(bs, c&EncircledFm != 0,
				zero || c&(mask21i|FramedFm) != 0,
				'5', '2')
			bs = appendCond(bs, c&OverlinedFm != 0,
				zero || c&(mask21i|FramedFm|EncircledFm) != 0,
				'5', '3')
		}

	}

	// foreground
	if c&maskFg != 0 {
		bs = c.appendFg(bs, zero)
	}

	// background
	if c&maskBg != 0 {
		bs = c.appendBg(bs, zero)
	}

	return bs
}

// ColorIndex is index of pre-defined 8-bit foreground or
// background colors from 0 to 255 (38;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 30–37 m)
//	  8- 15:  high intensity colors (as in ESC [ 90–97 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
type ColorIndex uint8

// GrayIndex from 0 to 23.
type GrayIndex uint8

// The Colored interface represents a value with a Color.
type Colored interface {
	Color() Color // color of the value
}

// Reset returns Color without a color and formats.
func (c Color) Reset() Color {
	return Color(0)
}

//
// Formats
//

// Bold or increased intensity (1).
func (c Color) Bold() Color {
	return (c &^ FaintFm) | BoldFm
}

// Faint, decreased intensity (2).
func (c Color) Faint() Color {
	return (c &^ BoldFm) | FaintFm
}

// DoublyUnderline or Bold off, double-underline
// per ECMA-48 (21).
func (c Color) DoublyUnderline() Color {
	return (c &^ UnderlineFm) | DoublyUnderlineFm
}

// Fraktur, rarely supported (20).
func (c Color) Fraktur() Color {
	return c | FrakturFm
}

// Italic, not widely supported, sometimes
// treated as inverse (3).
func (c Color) Italic() Color {
	return c | ItalicFm
}

// Underline (4).
func (c Color) Underline() Color {
	return (c &^ DoublyUnderlineFm) | UnderlineFm
}

// SlowBlink, blinking less than 150
// per minute (5).
func (c Color) SlowBlink() Color {
	return (c &^ RapidBlinkFm) | SlowBlinkFm
}

// RapidBlink, blinking 150+ per minute,
// not widely supported (6).
func (c Color) RapidBlink() Color {
	return (c &^ SlowBlinkFm) | RapidBlinkFm
}

// Blink is alias for the SlowBlink.
func (c Color) Blink() Color {
	return c.SlowBlink()
}

// Reverse video, swap foreground and
// background colors (7).
func (c Color) Reverse() Color {
	return c | ReverseFm
}

// Inverse is alias for the Reverse
func (c Color) Inverse() Color {
	return c.Reverse()
}

// Conceal, hidden, not widely supported (8).
func (c Color) Conceal() Color {
	return c | ConcealFm
}

// Hidden is alias for the Conceal
func (c Color) Hidden() Color {
	return c.Conceal()
}

// CrossedOut, characters legible, but
// marked for deletion (9).
func (c Color) CrossedOut() Color {
	return c | CrossedOutFm
}

// StrikeThrough is alias for the CrossedOut.
func (c Color) StrikeThrough() Color {
	return c.CrossedOut()
}

// Framed (51).
func (c Color) Framed() Color {
	return c | FramedFm
}

// Encircled (52).
func (c Color) Encircled() Color {
	return c | EncircledFm
}

// Overlined (53).
func (c Color) Overlined() Color {
	return c | OverlinedFm
}

// Foreground colors
//
// Black foreground color (30)
func (c Color) Black() Color {
	return (c &^ maskFg) | BlackFg
}

// Red foreground color (31)
func (c Color) Red() Color {
	return (c &^ maskFg) | RedFg
}

// Green foreground color (32)
func (c Color) Green() Color {
	return (c &^ maskFg) | GreenFg
}

// Yellow foreground color (33)
func (c Color) Yellow() Color {
	return (c &^ maskFg) | YellowFg
}

// Blue foreground color (34)
func (c Color) Blue() Color {
	return (c &^ maskFg) | BlueFg
}

// Magenta foreground color (35)
func (c Color) Magenta() Color {
	return (c &^ maskFg) | MagentaFg
}

// Cyan foreground color (36)
func (c Color) Cyan() Color {
	return (c &^ maskFg) | CyanFg
}

// White foreground color (37)
func (c Color) White() Color {
	return (c &^ maskFg) | WhiteFg
}

// Bright foreground colors
//
// BrightBlack foreground color (90)
func (c Color) BrightBlack() Color {
	return (c &^ maskFg) | BrightFg | BlackFg
}

// BrightRed foreground color (91)
func (c Color) BrightRed() Color {
	return (c &^ maskFg) | BrightFg | RedFg
}

// BrightGreen foreground color (92)
func (c Color) BrightGreen() Color {
	return (c &^ maskFg) | BrightFg | GreenFg
}

// BrightYellow foreground color (93)
func (c Color) BrightYellow() Color {
	return (c &^ maskFg) | BrightFg | YellowFg
}

// BrightBlue foreground color (94)
func (c Color) BrightBlue() Color {
	return (c &^ maskFg) | BrightFg | BlueFg
}

// BrightMagenta foreground color (95)
func (c Color) BrightMagenta() Color {
	return (c &^ maskFg) | BrightFg | MagentaFg
}

// BrightCyan foreground color (96)
func (c Color) BrightCyan() Color {
	return (c &^ maskFg) | BrightFg | CyanFg
}

// BrightWhite foreground color (97)
func (c Color) BrightWhite() Color {
	return (c &^ maskFg) | BrightFg | WhiteFg
}

// Other
//
// Index of pre-defined 8-bit foreground color
// from 0 to 255 (38;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 30–37 m)
//	  8- 15:  high intensity colors (as in ESC [ 90–97 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
func (c Color) Index(ci ColorIndex) Color {
	return (c &^ maskFg) | (Color(ci) << shiftFg) | flagFg
}

// Gray from 0 to 23.
func (c Color) Gray(n GrayIndex) Color {
	if n > 23 {
		n = 23
	}
	return (c &^ maskFg) | (Color(232+n) << shiftFg) | flagFg
}

// Background colors
//
// BgBlack background color (40)
func (c Color) BgBlack() Color {
	return (c &^ maskBg) | BlackBg
}

// BgRed background color (41)
func (c Color) BgRed() Color {
	return (c &^ maskBg) | RedBg
}

// BgGreen background color (42)
func (c Color) BgGreen() Color {
	return (c &^ maskBg) | GreenBg
}

// BgYellow background color (43)
func (c Color) BgYellow() Color {
	return (c &^ maskBg) | YellowBg
}

// BgBlue background color (44)
func (c Color) BgBlue() Color {
	return (c &^ maskBg) | BlueBg
}

// BgMagenta background color (45)
func (c Color) BgMagenta() Color {
	return (c &^ maskBg) | MagentaBg
}

// BgCyan background color (46)
func (c Color) BgCyan() Color {
	return (c &^ maskBg) | CyanBg
}

// BgWhite background color (47)
func (c Color) BgWhite() Color {
	return (c &^ maskBg) | WhiteBg
}

// Bright background colors
//
// BgBrightBlack background color (100)
func (c Color) BgBrightBlack() Color {
	return (c &^ maskBg) | BrightBg | BlackBg
}

// BgBrightRed background color (101)
func (c Color) BgBrightRed() Color {
	return (c &^ maskBg) | BrightBg | RedBg
}

// BgBrightGreen background color (102)
func (c Color) BgBrightGreen() Color {
	return (c &^ maskBg) | BrightBg | GreenBg
}

// BgBrightYellow background color (103)
func (c Color) BgBrightYellow() Color {
	return (c &^ maskBg) | BrightBg | YellowBg
}

// BgBrightBlue background color (104)
func (c Color) BgBrightBlue() Color {
	return (c &^ maskBg) | BrightBg | BlueBg
}

// BgBrightMagenta background color (105)
func (c Color) BgBrightMagenta() Color {
	return (c &^ maskBg) | BrightBg | MagentaBg
}

// BgBrightCyan background color (106)
func (c Color) BgBrightCyan() Color {
	return (c &^ maskBg) | BrightBg | CyanBg
}

// BgBrightWhite background color (107)
func (c Color) BgBrightWhite() Color {
	return (c &^ maskBg) | BrightBg | WhiteBg
}

// Other
//
// BgIndex of 8-bit pre-defined background color
// from 0 to 255 (48;5;n).
//
//	  0-  7:  standard colors (as in ESC [ 40–47 m)
//	  8- 15:  high intensity colors (as in ESC [100–107 m)
//	 16-231:  6 × 6 × 6 cube (216 colors): 16 + 36 × r + 6 × g + b (0 ≤ r, g, b ≤ 5)
//	232-255:  grayscale from black to white in 24 steps
func (c Color) BgIndex(n ColorIndex) Color {
	return (c &^ maskBg) | (Color(n) << shiftBg) | flagBg
}

// BgGray from 0 to 23.
func (c Color) BgGray(n GrayIndex) Color {
	if n > 23 {
		n = 23
	}
	return (c &^ maskBg) | (Color(232+n) << shiftBg) | flagBg
}
