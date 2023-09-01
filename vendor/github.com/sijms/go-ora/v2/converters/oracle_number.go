// 2022/9/13 Bin Liu <bin.liu@enmotech.com>

package converters

import (
	"encoding/hex"
	"fmt"
	"math"
	"unsafe"
)

const (
	Infinity              = "Infinity"
	InvalidInputNumberMsg = "Invalid Input Number %s "
)

var (
	Int64MaxByte  = []byte{202, 10, 23, 34, 73, 4, 69, 55, 78, 59, 8}
	Int64MinByte  = []byte{53, 92, 79, 68, 29, 98, 33, 47, 24, 43, 93, 102}
	Uint64MinByte = []byte{128}
	Uint64MaxByte = []byte{202, 19, 45, 68, 45, 8, 38, 10, 56, 17, 16}
)

// Number Convert Oracle Number Internal storage format to String
// Refer to oracle jdbc
type Number struct {
	data []byte
}

func NewNumber(b []byte) *Number {
	return &Number{data: b}
}

func (num *Number) String() (string, error) {
	return NumberToString(num.data)
}

func (num *Number) Int64() (int64, error) {
	return NumberToInt64(num.data)
}

func (num *Number) UInt64() (uint64, error) {
	return NumberToUInt64(num.data)
}

func NumberToString(b []byte) (string, error) {
	rb, err := toBytes(b)
	if err != nil {
		return "", err
	}
	if len(rb) == 0 {
		return "", fmt.Errorf(InvalidInputNumberMsg, hex.EncodeToString(b))
	}
	return *(*string)(unsafe.Pointer(&rb)), err
}

func NumberToInt64(data []byte) (int64, error) {
	return toInt64Internal(data, Int64MaxByte, Int64MinByte)
}

func NumberToUInt64(data []byte) (uint64, error) {
	return toUInt64Internal(data, Uint64MaxByte, Uint64MinByte)
}

// func StringToNumber(s string) ([]byte, error) {
// 	return ByteToNumber([]byte(s))
// }

// func ByteToNumber(b []byte) ([]byte, error) {
// 	if b[0] == '-' {
// 		return _toLnxFmt(b[1:], true), nil
// 	}
// 	return _toLnxFmt(b, false), nil
// }

func toBytes(b []byte) ([]byte, error) {
	if _isZero(b) {
		return []byte("0"), nil
	} else if _isPosInf(b) {
		return []byte("Infinity"), nil
	} else if _isNegInf(b) {
		return []byte("Infinity"), nil
	} else if !isValid(b) {
		return nil, fmt.Errorf(InvalidInputNumberMsg, hex.EncodeToString(b))
	}
	var (
		pos     = 0
		dataLen int // data length for after convert
	)
	// convert normal byte
	data := _fromLnxFmt(b)
	exponent := int(data[0]) // Unsigned integers do not appear negative
	if exponent > 127 {
		exponent = exponent - 256
	}
	realDataLen := len(data) - 1
	k := exponent - (realDataLen - 1)
	if k >= 0 {
		dataLen = 2*(exponent+1) + 1
	} else if exponent >= 0 {
		dataLen = 2 * (realDataLen + 1)
	} else {
		dataLen = 2*(realDataLen-exponent) + 3
	}

	result := make([]byte, dataLen)
	if !_isPositive(b) {
		result[pos] = '-'
		pos++
	}
	var b1 int
	if k >= 0 {
		pos += _byteToChars(data[1], result, pos)
		for b1 = 2; b1 <= realDataLen; exponent-- {
			_byteTo2Chars(data[b1], result, pos)
			pos += 2
			b1++
		}
		if exponent > 0 {
			for exponent > 0 {
				result[pos] = '0'
				pos++
				result[pos] = '0'
				pos++
				exponent--
			}
		}
	} else {
		n := realDataLen + k
		if n > 0 {
			pos += _byteToChars(data[1], result, pos)
			if n == 1 {
				result[pos] = '.'
				pos++
			}
			for b1 = 2; b1 < realDataLen; b1++ {
				_byteTo2Chars(data[b1], result, pos)
				pos += 2
				if n == b1 {
					result[pos] = '.'
					pos++
				}
			}
			if data[b1]%10 == 0 {
				pos += _byteToChars(data[b1]/10, result, pos)
			} else {
				_byteTo2Chars(data[b1], result, pos)
				pos += 2
			}
		} else {
			result[pos] = '0'
			pos++
			result[pos] = '.'
			pos++
			for n < 0 {
				n++
				result[pos] = '0'
				pos++
				result[pos] = '0'
				pos++
			}

			for b1 = 1; b1 < realDataLen; b1++ {
				_byteTo2Chars(data[b1], result, pos)
				pos += 2
			}

			if data[b1]%10 == 0 {
				pos += _byteToChars(data[b1]/10, result, pos)
			} else {
				_byteTo2Chars(data[b1], result, pos)
				pos += 2
			}
		}
	}
	return result[:pos], nil
}

func toInt64Internal(data, max, min []byte) (int64, error) {
	if _isZero(data) {
		return 0, nil
	}
	if _isInf(data) || compareBytes(data, max) > 0 ||
		compareBytes(data, min) < 0 {
		return 0, fmt.Errorf("Overflow Exception ")
	}
	return toInt64(data)
}

func toUInt64Internal(data, max, min []byte) (uint64, error) {
	if _isZero(data) {
		return 0, nil
	}
	if _isInf(data) || compareBytes(data, max) > 0 ||
		compareBytes(data, min) < 0 {
		return 0, fmt.Errorf("Overflow Exception ")
	}
	return toUInt64(data)
}

func toInt64(data []byte) (int64, error) {
	positive := _isPositive(data)
	var (
		b1 int
		b2 int
		b3 int
	)
	if positive {
		b1 = int(data[0]&0x7f - 65)
	} else {
		b1 = int(((data[0] ^ 0xFF) & 0x7F) - 65)
	}
	if positive || (len(data) == 21 && data[20] != 102) {
		b2 = len(data) - 1
	} else {
		b2 = len(data) - 2
	}
	if b2 > b1+1 {
		b3 = b1 + 1
	} else {
		b3 = b2
	}
	var l int64
	if positive {
		for i := 0; i < b3; i++ {
			l = l*100 + (int64(data[i+1]) - 1)
		}
	} else {
		for i := 0; i < b3; i++ {
			l = l*100 + (101 - int64(data[i+1]))
		}
	}
	for i := b1 - b2; i >= 0; i-- {
		l *= 100
	}
	if positive {
		return l, nil
	}
	return -l, nil
}

func toUInt64(data []byte) (uint64, error) {
	positive := _isPositive(data)
	if !positive {
		return 0, fmt.Errorf("Overflow Exception ")
	}
	var (
		b1 int
		b2 int
		b3 int
	)
	b1 = int(data[0]&0x7f - 65)
	if positive || (len(data) == 21 && data[20] != 102) {
		b2 = len(data) - 1
	} else {
		b2 = len(data) - 2
	}
	if b2 > b1+1 {
		b3 = b1 + 1
	} else {
		b3 = b2
	}
	var l uint64
	for i := 0; i < b3; i++ {
		l = l*100 + (uint64(data[i+1]) - 1)
	}
	for i := b1 - b2; i >= 0; i-- {
		l *= 100
	}
	return l, nil
}

// 长度为1且第一位为0x80 129
func _isZero(b []byte) bool {
	return b[0] == 128 && len(b) == 1
}

func _isNegInf(b []byte) bool {
	return b[0] == 0 && len(b) == 1
}

func _isPosInf(b []byte) bool {
	// -1 =255
	return len(b) == 2 && b[0] == 255 && b[1] == 101
}

func _isPositive(b []byte) bool {
	return (b[0] & 128) != 0
}

func _isInf(b []byte) bool {
	if (len(b) == 2 && b[0] == 255 && b[1] == 101) || (b[0] == 0 && len(b) == 1) {
		return true
	}
	return false
}

func isValid(b []byte) bool {
	var (
		dataLen  = len(b)
		tempByte byte
		pos      int
	)
	if _isPositive(b) {
		if dataLen == 1 {
			return _isZero(b)
		} else if b[0] == 255 && b[1] == 101 {
			return dataLen == 2
		} else if dataLen > 21 {
			return false
		} else if b[1] >= 2 && b[dataLen-1] >= 2 {
			for pos = 1; pos < dataLen; pos++ {
				tempByte = b[pos]
				if tempByte < 1 || tempByte > 100 {
					return false
				}
			}
			return true
		} else {
			return false
		}
	} else if dataLen < 3 {
		return _isNegInf(b)
	} else if dataLen > 21 {
		return false
	} else {
		if b[dataLen-1] != 102 {
			if dataLen <= 20 {
				return false
			}
		} else {
			dataLen--
		}
		if b[1] <= 100 && b[dataLen-1] <= 100 {
			for pos = 1; pos < dataLen; pos++ {
				tempByte = b[pos]
				if tempByte < 2 || tempByte > 101 {
					return false
				}
			}
			return true
		} else {
			return false
		}
	}
}

func _fromLnxFmt(b []byte) []byte {
	bLen := len(b)
	var newData []byte
	if _isPositive(b) {
		newData = make([]byte, bLen)
		newData[0] = b[0]&0x7f - 65
		for i := 1; i < bLen; i++ {
			newData[i] = b[i] - 1
		}
	} else {
		if bLen-1 == 20 && b[bLen-1] != 102 {
			newData = make([]byte, bLen)
		} else {
			newData = make([]byte, bLen-1)
		}

		newData[0] = ((b[0] ^ 0xFF) & 0x7F) - 65
		for i := 1; i < len(newData); i++ {
			newData[i] = 101 - b[i]
		}
	}
	return newData
}

// func _toLnxFmt(b []byte, negative bool) []byte {
// 	var data []byte
// 	l := len(b)
// 	if !negative {
// 		fmt.Println(b)
// 		data = make([]byte, l)
// 		data[0] = b[0] + 128 + 64 + 1
// 		for i := 1; i < l; i++ {
// 			data[i] = b[i] + 1
// 		}
// 	} else {
// 		if l-1 < 20 {
// 			data = make([]byte, l+1)
// 		} else {
// 			data = make([]byte, l)
// 		}
// 		data[0] = b[0] + 128 + 64 + 1 ^ 0xFF
// 		var i int
// 		for i = 1; i < l; i++ {
// 			data[i] = 101 - b[i]
// 		}
// 		if i <= 20 {
// 			data[i] = 102
// 		}
// 	}
// 	return data
// }

func _byteToChars(paramByte byte, result []byte, pos int) int {
	if paramByte < 0 {
		return 0
	} else if paramByte < 10 {
		result[pos] = 48 + paramByte
		return 1
	} else if paramByte < 100 {
		result[pos] = 48 + paramByte/10
		result[pos+1] = 48 + paramByte%10
		return 2
	} else {
		result[pos] = '1'
		result[pos+1] = 48 + paramByte/10 - 10
		result[pos+2] = 48 + paramByte%10
		return 3
	}
}

func _byteTo2Chars(paramByte byte, result []byte, pos int) {
	if paramByte < 0 {
		result[pos] = '0'
		result[pos+1] = '0'
	} else if paramByte < 10 {
		result[pos] = '0'
		result[pos+1] = 48 + paramByte
	} else if paramByte < 100 {
		result[pos] = 48 + paramByte/10
		result[pos+1] = 48 + paramByte%10
	} else {
		result[pos] = '0'
		result[pos+1] = '0'
	}
}

func CompareBytes(byte1, byte2 []byte) int {
	return compareBytes(byte1, byte2)
}

func compareBytes(byte1, byte2 []byte) int {
	i := len(byte1)
	j := len(byte2)
	b := 0
	k := math.Min(float64(i), float64(j))
	var (
		m, n = 0, 0
	)
	for b < int(k) {
		m = int(byte1[b] & 0xFF)
		n = int(byte2[b] & 0xFF)
		if m != n {
			if m < n {
				return -1
			}
			return 1
		}
		b++
	}
	if i == j {
		return 0
	}

	if i > j {
		return 1
	}
	return -1
}
