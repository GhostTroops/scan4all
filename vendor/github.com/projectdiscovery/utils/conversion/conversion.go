package conversion

import "unsafe"

func Bytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func String(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
