package timeutil

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RFC3339ToTime converts RFC3339 (standard extended go) to time
func RFC3339ToTime(s interface{}) (time.Time, error) {
	return time.Parse(time.RFC3339, fmt.Sprint(s))
}

// MsToTime converts uint64/int64 milliseconds to go time.Time
func MsToTime(i64 interface{}) time.Time {
	// 1ms = 1000000ns
	switch v := i64.(type) {
	case int64:
		return time.Unix(0, v*1000000)
	case uint64:
		return time.Unix(0, int64(v)*1000000)
	case string:
		return MsToTime(stringToInt(fmt.Sprint(i64)))
	}
	return time.Time{}
}

func SToTime(i64 interface{}) time.Time {
	switch v := i64.(type) {
	case int64:
		return time.Unix(v, 0)
	case uint64:
		return time.Unix(int64(v), 0)
	case string:
		return SToTime(stringToInt(fmt.Sprint(i64)))
	}
	return time.Now()
}

func stringToInt(s string) interface{} {
	if u, err := strconv.ParseInt(s, 0, 64); err == nil {
		return u
	}
	if u, err := strconv.ParseUint(s, 0, 64); err == nil {
		return u
	}

	return 0
}

func ParseUnixTimestamp(s string) (time.Time, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(i, 0), nil
}

// ParseDuration is similar to time.ParseDuration but also supports days unit
// if the unit is omitted, it defaults to seconds
func ParseDuration(s string) (time.Duration, error) {
	s = strings.ToLower(s)
	// default to sec
	if _, err := strconv.Atoi(s); err == nil {
		s = s + "s"
	}
	// parse days unit as hours
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		if days, err := strconv.Atoi(s); err == nil {
			s = strconv.Itoa(days*24) + "h"
		}
	}
	return time.ParseDuration(s)
}
