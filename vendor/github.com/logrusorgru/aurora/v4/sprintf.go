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

type tailedValue struct {
	Value
	tail Color
}

func (v *tailedValue) Format(s fmt.State, verb rune) {

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

	var (
		format = make([]byte, 0, 128)
		color  = v.Color()
	)
	if color != 0 {
		format = append(format, esc...)
		format = color.appendNos(format, v.tail != 0)
		format = append(format, 'm')
	}
	format = append(format, '%')
	var f byte
	for i := 0; i < len(availFlags); i++ {
		if f = availFlags[i]; s.Flag(int(f)) {
			format = append(format, f)
		}
	}
	var width, prec int
	var ok bool
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
		if v.tail != 0 {
			// set next (previous) format clearing current one
			format = append(format, esc...)
			format = v.tail.appendNos(format, true)
			format = append(format, 'm')
		} else {
			format = append(format, clear...) // just clear
		}
	}
	fmt.Fprintf(s, string(format), v.Value.Value())
}

func sprintf(format interface{}, args ...interface{}) string {
	switch ft := format.(type) {
	case string:
		return fmt.Sprintf(ft, args...)
	case Value:
		for i, v := range args {
			if val, ok := v.(Value); ok {
				args[i] = &tailedValue{Value: val, tail: ft.Color()}
				continue
			}
		}
		return fmt.Sprintf(ft.String(), args...)
	}
	// unknown type of format (we hope it's a string)
	return fmt.Sprintf(fmt.Sprint(format), args...)
}
