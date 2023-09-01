package converters

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

/*
BINARY_FLOAT and BINARY_DOUBLE encoding observed using
SELECT dump(cast(xxx as binary_yyy) FROM dual;
*/
func EncodeBool(val bool) []byte {
	if val {
		return []byte{1, 1}
	} else {
		return []byte{1, 0}
	}
}

func DecodeBool(data []byte) bool {
	return bytes.Compare(data, []byte{1, 1}) == 0
}

func ConvertBinaryFloat(bytes []byte) float32 {
	if bytes[0]&128 != 0 {
		bytes[0] = bytes[0] & 127
	} else {
		bytes[0] = ^bytes[0]
		bytes[1] = ^bytes[1]
		bytes[2] = ^bytes[2]
		bytes[3] = ^bytes[3]
	}
	u := binary.BigEndian.Uint32(bytes)
	return math.Float32frombits(u)
	//if u > (1 << 31) {
	//	return -math.Float32frombits(u)
	//}
	//return math.Float32frombits(^u)
}

func ConvertBinaryDouble(bytes []byte) float64 {
	if bytes[0]&128 != 0 {
		bytes[0] = bytes[0] & 127
	} else {
		bytes[0] = ^bytes[0]
		bytes[1] = ^bytes[1]
		bytes[2] = ^bytes[2]
		bytes[3] = ^bytes[3]
		bytes[4] = ^bytes[4]
		bytes[5] = ^bytes[5]
		bytes[6] = ^bytes[6]
		bytes[7] = ^bytes[7]
	}
	u := binary.BigEndian.Uint64(bytes)
	return math.Float64frombits(u)
	//if neg {
	//	out = -out
	//}
	//return out
	//if u > (1 << 63) {
	//	out = -out
	//}
	//return math.Float64frombits(u)
	//return math.Float64frombits(^u)
}

/*
INTERVAL_xxx encoding described at https://www.orafaq.com/wiki/Interval
*/

func ConvertIntervalYM_DTY(val []byte) string {
	/*
	   The first 4 bytes gives the number of years, the fifth byte gives the number of months in the following format:
	   years + 2147483648
	   months + 60
	*/
	uyears := binary.BigEndian.Uint32(val)
	years := int(uyears - uint32(2147483648))
	if years >= 0 {
		months := val[4] - 60
		return fmt.Sprintf("+%02d-%02d", years, months)
	}
	years = -years
	months := val[4] - 40
	return fmt.Sprintf("-%02d-%02d", years, months)
}

func ConvertIntervalDS_DTY(val []byte) string {
	/*
	   The first 4 bytes gives the number of days, the last 4 ones the number of nanoseconds and the 3 in the middle the number of hours, minutes and seconds in the following format:

	   days + 2147483648
	   hours + 60
	   minutes + 60
	   seconds + 60
	   nanoseconds
	*/
	udays := binary.BigEndian.Uint32(val)
	days := int(udays - uint32(2147483648))
	if days >= 0 {
		hours := val[4] - 60
		mins := val[5] - 60
		secs := val[6] - 60
		uns := binary.BigEndian.Uint32(val[7:])
		ns := (int(uns - uint32(2147483648))) / 1000
		return fmt.Sprintf("+%02d %02d:%02d:%02d.%06d", days, hours, mins, secs, ns)
	}
	days = -days
	hours := 60 - val[4]
	mins := 60 - val[5]
	secs := 60 - val[6]
	uns := binary.BigEndian.Uint32(val[7:])
	ns := -(int(uns - uint32(2147483648))) / 1000
	return fmt.Sprintf("-%02d %02d:%02d:%02d.%06d", days, hours, mins, secs, ns)
}
