package chinese

import (
	"golang.org/x/text/encoding/simplifiedchinese"
	"unicode/utf8"
)

func ByteToGBK(strBuf []byte) []byte {
	if isUtf8(strBuf) {
		if GBKBuf, err := simplifiedchinese.GBK.NewEncoder().Bytes(strBuf); err == nil {
			if isUtf8(GBKBuf) == false {
				return GBKBuf
			}
		}
		if GB18030Buf, err := simplifiedchinese.GB18030.NewEncoder().Bytes(strBuf); err == nil {
			if isUtf8(GB18030Buf) == false {
				return GB18030Buf
			}
		}
		return strBuf
	} else {
		return strBuf
	}
}

func ByteToUTF8(strBuf []byte) []byte {
	if isUtf8(strBuf) {
		return strBuf
	} else {
		if GBKBuf, err := simplifiedchinese.GBK.NewDecoder().Bytes(strBuf); err == nil {
			if isUtf8(GBKBuf) == true {
				return GBKBuf
			}
		}
		if GB18030Buf, err := simplifiedchinese.GB18030.NewDecoder().Bytes(strBuf); err == nil {
			if isUtf8(GB18030Buf) == true {
				return GB18030Buf
			}
		}
		return strBuf
	}
}

func ToGBK(str string) string {
	strBuf := []byte(str)
	GBKBuf := ByteToGBK(strBuf)
	return string(GBKBuf)

}

func ToUTF8(str string) string {
	strBuf := []byte(str)
	Utf8Buf := ByteToUTF8(strBuf)
	return string(Utf8Buf)
}

func isUtf8(buf []byte) bool {
	return utf8.Valid(buf)
}
