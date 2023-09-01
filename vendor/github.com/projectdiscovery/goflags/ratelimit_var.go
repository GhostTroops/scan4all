package goflags

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	stringsutil "github.com/projectdiscovery/utils/strings"
	timeutil "github.com/projectdiscovery/utils/time"
)

var (
	MaxRateLimitTime   = time.Minute // anything above time.Minute is not practical (for our use case)
	rateLimitOptionMap map[*RateLimitMap]Options
)

func init() {
	rateLimitOptionMap = make(map[*RateLimitMap]Options)
}

type RateLimit struct {
	MaxCount uint
	Duration time.Duration
}

type RateLimitMap struct {
	kv map[string]RateLimit
}

// Set inserts a value to the map. Format: key=value
func (rateLimitMap *RateLimitMap) Set(value string) error {
	if rateLimitMap.kv == nil {
		rateLimitMap.kv = make(map[string]RateLimit)
	}

	option, ok := rateLimitOptionMap[rateLimitMap]
	if !ok {
		option = StringSliceOptions
	}
	rateLimits, err := ToStringSlice(value, option)
	if err != nil {
		return err
	}

	for _, rateLimit := range rateLimits {
		var k, v string
		if idxSep := strings.Index(rateLimit, kvSep); idxSep > 0 {
			k = rateLimit[:idxSep]
			v = rateLimit[idxSep+1:]
		}

		// note:
		// - inserting multiple times the same key will override the previous v
		// - empty string is legitimate rateLimit
		if k != "" {
			rateLimit, err := parseRateLimit(v)
			if err != nil {
				return err
			}
			rateLimitMap.kv[k] = rateLimit
		}
	}
	return nil
}

// Del removes the specified key
func (rateLimitMap *RateLimitMap) Del(key string) error {
	if rateLimitMap.kv == nil {
		return errors.New("empty runtime map")
	}
	delete(rateLimitMap.kv, key)
	return nil
}

// IsEmpty specifies if the underlying map is empty
func (rateLimitMap *RateLimitMap) IsEmpty() bool {
	return rateLimitMap.kv == nil || len(rateLimitMap.kv) == 0
}

// AsMap returns the internal map as reference - changes are allowed
func (rateLimitMap *RateLimitMap) AsMap() map[string]RateLimit {
	return rateLimitMap.kv
}

func (rateLimitMap RateLimitMap) String() string {
	defaultBuilder := &strings.Builder{}
	defaultBuilder.WriteString("{")

	var items string
	for k, v := range rateLimitMap.kv {
		items += fmt.Sprintf("\"%s\":\"%d/%s\",", k, v.MaxCount, v.Duration.String())
	}
	defaultBuilder.WriteString(stringsutil.TrimSuffixAny(items, ",", ":"))
	defaultBuilder.WriteString("}")
	return defaultBuilder.String()
}

// RateLimitMapVar adds a ratelimit flag with a longname
func (flagSet *FlagSet) RateLimitMapVar(field *RateLimitMap, long string, defaultValue []string, usage string, options Options) *FlagData {
	return flagSet.RateLimitMapVarP(field, long, "", defaultValue, usage, options)
}

// RateLimitMapVarP adds a ratelimit flag with a short name and long name.
// It is equivalent to RateLimitMapVar, and also allows specifying ratelimits in days (e.g., "hackertarget=2/d" 2 requests per day, which is equivalent to 24h).
func (flagSet *FlagSet) RateLimitMapVarP(field *RateLimitMap, long, short string, defaultValue StringSlice, usage string, options Options) *FlagData {
	if field == nil {
		panic(fmt.Errorf("field cannot be nil for flag -%v", long))
	}

	rateLimitOptionMap[field] = options
	for _, defaultItem := range defaultValue {
		values, _ := ToStringSlice(defaultItem, options)
		for _, value := range values {
			if err := field.Set(value); err != nil {
				panic(fmt.Errorf("failed to set default value for flag -%v: %v", long, err))
			}
		}
	}

	flagData := &FlagData{
		usage:        usage,
		long:         long,
		defaultValue: defaultValue,
		skipMarshal:  true,
	}
	if short != "" {
		flagData.short = short
		flagSet.CommandLine.Var(field, short, usage)
		flagSet.flagKeys.Set(short, flagData)
	}
	flagSet.CommandLine.Var(field, long, usage)
	flagSet.flagKeys.Set(long, flagData)
	return flagData
}

func parseRateLimit(s string) (RateLimit, error) {
	sArr := strings.Split(s, "/")

	if len(sArr) < 2 {
		return RateLimit{}, errors.New("parse error: expected format k=v/d (e.g., scanme.sh=10/s got " + s)
	}

	maxCount, err := strconv.ParseUint(sArr[0], 10, 64)
	if err != nil {
		return RateLimit{}, errors.New("parse error: " + err.Error())
	}
	timeValue := sArr[1]
	if len(timeValue) > 0 {
		// check if time is given ex: 1s
		// if given value is just s (add prefix 1)
		firstChar := timeValue[0]
		if !unicode.IsDigit(rune(firstChar)) {
			timeValue = "1" + timeValue
		}
	}

	duration, err := timeutil.ParseDuration(timeValue)
	if err != nil {
		return RateLimit{}, errors.New("parse error: " + err.Error())
	}

	if MaxRateLimitTime < duration {
		return RateLimit{}, fmt.Errorf("duration cannot be more than %v but got %v", MaxRateLimitTime, duration)
	}

	return RateLimit{MaxCount: uint(maxCount), Duration: duration}, nil
}
