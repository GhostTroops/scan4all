package clistats

import (
	"fmt"
	"strconv"
	"time"
)

// String returns the string representation of a few different types that are simple
// enough to be represented as a static metric for stats.
//
// For everything else, it uses fmt.Sprint but it is very recommended to use
// only small and easy types.
func String(from interface{}) string {
	// Special case for nil values
	if from == nil {
		return "n/a"
	}

	switch T := from.(type) {
	case string:
		return T
	case fmt.Stringer:
		return T.String()
	case bool:
		return strconv.FormatBool(T)
	case int:
		return strconv.FormatInt(int64(T), 10)
	case int32:
		return strconv.FormatInt(int64(T), 10)
	case int64:
		return strconv.FormatInt(T, 10)
	case uint32:
		return strconv.FormatUint(uint64(T), 10)
	case uint64:
		return strconv.FormatUint(T, 10)
	case float32:
		return strconv.FormatFloat(float64(T), 'E', -1, 32)
	case float64:
		return strconv.FormatFloat(T, 'E', -1, 64)
	case []byte:
		return string(T)
	case *[]byte:
		return string(*T)
	case *string:
		return *T
	default:
		return fmt.Sprintf("%v", from)
	}
}

// FmtDuration formats the duration for the time elapsed
func FmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}
