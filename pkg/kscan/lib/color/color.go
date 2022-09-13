package color

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

var (
	mod      = 0
	colorMap = map[string]int{
		//varyImportant
		"white": 30,
		"red":   31,
		//Important
		"green":  32,
		"yellow": 33,
		"blue":   34,
		"purple": 35,
		"cyan":   36,
		"black":  37,
	}
	backgroundMap = map[string]int{
		"white":  40,
		"red":    41,
		"green":  42,
		"yellow": 43,
		"blue":   44,
		"purple": 45,
		"cyan":   46,
		"black":  47,
	}
	formatMap = map[string]int{
		"bold":      1,
		"italic":    3,
		"underline": 4,
		"overturn":  7,
	}
)

//mod = 0 则为不输出颜色;
//mod = 1 则依据ANSI转义序列输出颜色体系;
func init() {
	mod = 0
}

func convANSI(s string, color int, background int, format []int) string {
	if mod == 0 {
		return s
	}
	var formatStrArr []string
	var option string
	for _, i := range format {
		formatStrArr = append(formatStrArr, strconv.Itoa(i))
	}
	if background != 0 {
		formatStrArr = append(formatStrArr, strconv.Itoa(background))
	}
	if color != 0 {
		formatStrArr = append(formatStrArr, strconv.Itoa(color))
	}
	option = strings.Join(formatStrArr, ";")
	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", option, s)
}

func convColor(s string, color string) string {
	return convANSI(s, colorMap[color], 0, []int{})
}
func convBackground(s string, color string) string {
	return convANSI(s, 0, backgroundMap[color], []int{})
}

func convFormats(s string, formats []int) string {
	return convANSI(s, 0, 0, formats)
}

func convFormat(s string, format string) string {
	return convFormats(s, []int{formatMap[format]})
}

func Bold(s string) string {
	return convFormat(s, "bold")
}

func Italic(s string) string {
	return convFormat(s, "italic")
}

func Underline(s string) string {
	return convFormat(s, "underline")
}

func Overturn(s string) string {
	return convFormat(s, "overturn")
}

func Red(s string) string {
	return convColor(s, "red")
}
func RedB(s string) string {
	return convBackground(s, "red")
}

func White(s string) string {
	return convColor(s, "white")
}
func WhiteB(s string) string {
	return convBackground(s, "white")
}

func Yellow(s string) string {
	return convColor(s, "yellow")
}
func YellowB(s string) string {
	return convBackground(s, "yellow")
}

func Green(s string) string {
	return convColor(s, "green")
}
func GreenB(s string) string {
	return convBackground(s, "green")
}

func Purple(s string) string {
	return convColor(s, "purple")
}
func PurpleB(s string) string {
	return convBackground(s, "purple")
}

func Cyan(s string) string {
	return convColor(s, "cyan")
}
func CyanB(s string) string {
	return convBackground(s, "cyan")
}

func Blue(s string) string {
	return convColor(s, "blue")
}
func BlueB(s string) string {
	return convBackground(s, "blue")
}

func Black(s string) string {
	return convColor(s, "black")
}

func BlackB(s string) string {
	return convBackground(s, "black")
}

func Important(s string) string {
	s = Red(s)
	s = Bold(s)
	s = Overturn(s)
	return s
}

func Warning(s string) string {
	s = Yellow(s)
	s = Bold(s)
	s = Overturn(s)
	return s
}

func Tips(s string) string {
	s = Green(s)
	return s
}

func Random(s string) string {
	return convANSI(s, rand.Intn(len(colorMap))+30, 0, []int{})
}

func RandomImportant(s string) string {
	r := rand.Intn(len(colorMap)-2) + 32
	return convANSI(s, r, r, []int{7})
}

func StrSliceRandomColor(strSlice []string) string {
	var s string
	for _, value := range strSlice {
		s += RandomImportant(value)
		s += ", "
	}
	return s[:len(s)-2]
}

func StrMapRandomColor(m map[string]string, printKey bool, importantKey []string, varyImportantKey []string) string {
	var s string
	if len(m) == 0 {
		return ""
	}
	for key, value := range m {
		var cell string
		if printKey {
			cell += key + ":"
		}
		cell += value

		if isInStrArr(importantKey, key) {
			cell = RandomImportant(cell)
		} else if isInStrArr(varyImportantKey, key) {
			cell = Red(Overturn(cell))
		} else {
			cell = Random(cell)

		}
		s += cell + ", "
	}
	return s[:len(s)-2]
}

func isInStrArr(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
