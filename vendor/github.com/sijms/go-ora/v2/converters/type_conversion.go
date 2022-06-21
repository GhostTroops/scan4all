package converters

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"time"
)

const (
	maxConvertibleInt    = (1 << 63) - 1
	maxConvertibleNegInt = (1 << 63)
)

// EncodeDate convert time.Time into oracle representation
func EncodeDate(ti time.Time) []byte {
	ret := make([]byte, 7)
	ret[0] = uint8(ti.Year()/100 + 100)
	ret[1] = uint8(ti.Year()%100 + 100)
	ret[2] = uint8(ti.Month())
	ret[3] = uint8(ti.Day())
	ret[4] = uint8(ti.Hour() + 1)
	ret[5] = uint8(ti.Minute() + 1)
	ret[6] = uint8(ti.Second() + 1)
	return ret
}

func EncodeTimeStamp(ti time.Time) []byte {
	ret := make([]byte, 11)
	ret[0] = uint8(ti.Year()/100 + 100)
	ret[1] = uint8(ti.Year()%100 + 100)
	ret[2] = uint8(ti.Month())
	ret[3] = uint8(ti.Day())
	ret[4] = uint8(ti.Hour() + 1)
	ret[5] = uint8(ti.Minute() + 1)
	ret[6] = uint8(ti.Second() + 1)
	binary.BigEndian.PutUint32(ret[7:11], uint32(ti.Nanosecond()))
	return ret

}

// DecodeDate convert oracle time representation into time.Time
func DecodeDate(data []byte) (time.Time, error) {
	if len(data) < 7 {
		return time.Now(), errors.New("abnormal data representation for date")
	}
	year := (int(data[0]) - 100) * 100
	year += int(data[1]) - 100
	nanoSec := 0
	if len(data) > 7 {
		nanoSec = int(binary.BigEndian.Uint32(data[7:11]))
	}
	tzHour := 0
	tzMin := 0
	if len(data) > 11 {
		tzHour = int(data[11]) - 20
		tzMin = int(data[12]) - 60
	}
	if tzHour == 0 && tzMin == 0 {
		return time.Date(year, time.Month(data[2]), int(data[3]),
			int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, time.UTC), nil
	}
	loc, err := time.Parse("-0700", fmt.Sprintf("%+03d%02d", tzHour, tzMin))
	if err != nil {
		return time.Date(year, time.Month(data[2]), int(data[3]),
			int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, time.UTC), nil
	} else {
		return time.Date(year, time.Month(data[2]), int(data[3]),
			int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, loc.Location()), nil
	}
	//return time.Date(year, time.Month(data[2]), int(data[3]),
	//	int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, time.UTC), nil
}

// addDigitToMantissa return the mantissa with the added digit if the carry is not
// set by the add. Othervise, return the mantissa untouched and carry = true.
func addDigitToMantissa(mantissaIn uint64, d byte) (mantissaOut uint64, carryOut bool) {
	var carry uint64
	mantissaOut = mantissaIn

	if mantissaIn != 0 {
		var over uint64
		over, mantissaOut = bits.Mul64(mantissaIn, uint64(10))
		if over != 0 {
			return mantissaIn, true
		}
	}
	mantissaOut, carry = bits.Add64(mantissaOut, uint64(d), carry)
	if carry != 0 {
		return mantissaIn, true
	}
	return mantissaOut, false
}

// FromNumber decode Oracle binary representation of numbers
// and returns mantissa, negative and exponent
// Some documentation:
//	https://gotodba.com/2015/03/24/how-are-numbers-saved-in-oracle/
//  https://www.orafaq.com/wiki/Number
func FromNumber(inputData []byte) (mantissa uint64, negative bool, exponent int, mantissaDigits int, err error) {
	if len(inputData) == 0 {
		return 0, false, 0, 0, fmt.Errorf("Invalid NUMBER")
	}
	if inputData[0] == 0x80 {
		return 0, false, 0, 0, nil
	}

	negative = inputData[0]&0x80 == 0
	if negative {
		exponent = int(inputData[0]^0x7f) - 64
	} else {
		exponent = int(inputData[0]&0x7f) - 64
	}

	buf := inputData[1:]
	// When negative, strip the last byte if equal 0x66
	if negative && inputData[len(inputData)-1] == 0x66 {
		buf = inputData[1 : len(inputData)-1]
	}

	carry := false // get true when mantissa exceeds 64 bits
	firstDigitWasZero := 0

	// Loop on mantissa digits, stop with the capacity of int64 is reached
	// Beyond, digits will be lost during convertion t
	mantissaDigits = 0
	for p, digit100 := range buf {
		if p == 0 {
			firstDigitWasZero = -1
		}
		digit100--
		if negative {
			digit100 = 100 - digit100
		}

		mantissa, carry = addDigitToMantissa(mantissa, digit100/10)
		if carry {
			break
		}
		mantissaDigits++

		mantissa, carry = addDigitToMantissa(mantissa, digit100%10)
		if carry {
			break
		}
		mantissaDigits++
	}

	exponent = exponent*2 - mantissaDigits // Adjust exponent to the retrieved mantissa
	return mantissa, negative, exponent, mantissaDigits + firstDigitWasZero, nil
}

// DecodeDouble decode NUMBER as a float64
// Please note limitations Oracle NUMBER can have 38 significant digits while
// Float64 have 51 bits. Convertion can't be perfect.
func DecodeDouble(inputData []byte) float64 {
	mantissa, negative, exponent, _, err := FromNumber(inputData)
	if err != nil {
		return math.NaN()
	}
	absExponent := int(math.Abs(float64(exponent)))
	if negative {
		return -math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)
	}
	return math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)

}

// DecodeInt convert NUMBER to int64
// Preserve all the possible bits of the mantissa when Int is between MinInt64 and MaxInt64 range
func DecodeInt(inputData []byte) int64 {
	mantissa, negative, exponent, _, err := FromNumber(inputData)
	if err != nil || exponent < 0 {
		return 0
	}

	for exponent > 0 {
		mantissa *= 10
		exponent--
	}
	if negative && (mantissa>>63) == 0 {
		return -int64(mantissa)
	}
	return int64(mantissa)
}

// DecodeNumber decode the given NUMBER and return an interface{} that could be either an int64 or a float64
//
// If the number can be represented by an integer it returns an int64
// Othervise, it returns a float64
//
// The sql.Parse will do the match with program need.
//
// Ex When parsing a float into an int64, the driver will try to cast the float64 into the int64.
// If the float64 can't be represented by an int64, Parse will issue an error "invalid syntax"
func DecodeNumber(inputData []byte) interface{} {
	var powerOfTen = [...]uint64{
		1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
		10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000,
		1000000000000000, 10000000000000000, 100000000000000000, 1000000000000000000,
		10000000000000000000}

	mantissa, negative, exponent, mantissaDigits, err := FromNumber(inputData)
	if err != nil {
		return math.NaN()
	}

	if mantissaDigits == 0 {
		return int64(0)
	}

	if exponent >= 0 && exponent < len(powerOfTen) {
		// exponent = mantissaDigits - exponent
		IntMantissa := mantissa
		IntExponent := exponent
		var over uint64
		over, IntMantissa = bits.Mul64(IntMantissa, powerOfTen[IntExponent])
		if (!negative && IntMantissa > maxConvertibleInt) ||
			(negative && IntMantissa > maxConvertibleNegInt) {
			goto fallbackToFloat
		}
		if over != 0 {
			goto fallbackToFloat
		}

		if negative && (IntMantissa>>63) == 0 {
			return -int64(IntMantissa)
		}
		return int64(IntMantissa)
	}

fallbackToFloat:
	//if negative {
	//	return -float64(mantissa) * math.Pow10(exponent)
	//}
	//
	//return float64(mantissa) * math.Pow10(exponent)
	absExponent := int(math.Abs(float64(exponent)))
	if negative {
		return -math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)
	}
	return math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)
}

// ToNumber encode mantissa, sign and exponent as a []byte expected by Oracle
func ToNumber(mantissa []byte, negative bool, exponent int) []byte {

	if len(mantissa) == 0 {
		return []byte{128}
	}

	if exponent%2 == 0 {
		mantissa = append([]byte{'0'}, mantissa...)
	} else {
	}

	mantissaLen := len(mantissa)
	size := 1 + (mantissaLen+1)/2
	if negative && mantissaLen < 21 {
		size++
	}
	buf := make([]byte, size, size)

	for i := 0; i < mantissaLen; i += 2 {
		b := 10 * (mantissa[i] - '0')
		if i < mantissaLen-1 {
			b += mantissa[i+1] - '0'
		}
		if negative {
			b = 100 - b
		}
		buf[1+i/2] = b + 1
	}

	if negative && mantissaLen < 21 {
		buf[len(buf)-1] = 0x66
	}

	if exponent < 0 {
		exponent--
	}
	exponent = (exponent / 2) + 1
	if negative {
		buf[0] = byte(exponent+64) ^ 0x7f
	} else {
		buf[0] = byte(exponent+64) | 0x80
	}
	return buf
}

// EncodeInt64 encode a int64 into an oracle NUMBER internal format
// Keep all significant bits of the int64
func EncodeInt64(val int64) []byte {
	mantissa := []byte(strconv.FormatInt(val, 10))
	negative := mantissa[0] == '-'
	if negative {
		mantissa = mantissa[1:]
	}
	exponent := len(mantissa) - 1
	trailingZeros := 0
	for i := len(mantissa) - 1; i >= 0 && mantissa[i] == '0'; i-- {
		trailingZeros++
	}
	mantissa = mantissa[:len(mantissa)-trailingZeros]
	return ToNumber(mantissa, negative, exponent)
}

// EncodeInt encode a int into an oracle NUMBER internal format
func EncodeInt(val int) []byte {
	return EncodeInt64(int64(val))
}

// EncodeDouble convert a float64 into binary NUMBER representation
func EncodeDouble(num float64) ([]byte, error) {
	if num == 0.0 {
		return []byte{128}, nil
	}

	var (
		exponent int
		err      error
	)
	mantissa := []byte(strconv.FormatFloat(num, 'e', -1, 64))
	if i := bytes.Index(mantissa, []byte{'e'}); i >= 0 {
		exponent, err = strconv.Atoi(string(mantissa[i+1:]))
		if err != nil {
			return nil, err
		}
		mantissa = mantissa[:i]
	}
	negative := mantissa[0] == '-'
	if negative {
		mantissa = mantissa[1:]
	}
	if i := bytes.Index(mantissa, []byte{'.'}); i >= 0 {
		mantissa = append(mantissa[:i], mantissa[i+1:]...)
	}
	return ToNumber(mantissa, negative, exponent), nil
}
