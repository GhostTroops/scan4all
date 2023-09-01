package goflags

import (
	"errors"
	"time"
	timeutil "github.com/projectdiscovery/utils/time"
)

type durationValue time.Duration

func newDurationValue(val time.Duration, p *time.Duration) *durationValue {
	*p = val
	return (*durationValue)(p)
}

func (d *durationValue) Set(s string) error {
	v, err := timeutil.ParseDuration(s)
	if err != nil {
		err = errors.New("parse error")
	}
	*d = durationValue(v)
	return err
}

func (d *durationValue) Get() any { return time.Duration(*d) }

func (d *durationValue) String() string { return (*time.Duration)(d).String() }

// DurationVar adds a duration flag with a longname
func (flagSet *FlagSet) DurationVar(field *time.Duration, long string, defaultValue time.Duration, usage string) *FlagData {
	return flagSet.DurationVarP(field, long, "", defaultValue, usage)
}

// DurationVarP adds a duration flag with a short name and long name.
// It is equivalent to DurationVar but also allows specifying durations in days (e.g., "2d" for 2 days, which is equivalent to 2*24h).
// The default unit for durations is seconds (ex: "10" => 10s).
func (flagSet *FlagSet) DurationVarP(field *time.Duration, long, short string, defaultValue time.Duration, usage string) *FlagData {
	flagData := &FlagData{
		usage:        usage,
		long:         long,
		defaultValue: defaultValue,
	}
	if short != "" {
		flagData.short = short
		flagSet.CommandLine.Var(newDurationValue(defaultValue, field), short, usage)
		flagSet.flagKeys.Set(short, flagData)
	}
	flagSet.CommandLine.Var(newDurationValue(defaultValue, field), long, usage)
	flagSet.flagKeys.Set(long, flagData)
	return flagData
}
