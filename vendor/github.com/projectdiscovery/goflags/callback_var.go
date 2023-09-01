package goflags

import (
	"fmt"
	"strconv"
)

// CallBackFunc
type CallBackFunc func()

// callBackVar
type callBackVar struct {
	Value CallBackFunc
}

// Set
func (c *callBackVar) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return fmt.Errorf("failed to parse callback flag")
	}
	if v {
		// if flag found execute callback
		c.Value()
	}
	return nil
}

// IsBoolFlag
func (c *callBackVar) IsBoolFlag() bool {
	return true
}

// String
func (c *callBackVar) String() string {
	return "false"
}

// CallbackVar adds a Callback flag with a longname
func (flagSet *FlagSet) CallbackVar(callback CallBackFunc, long string, usage string) *FlagData {
	return flagSet.CallbackVarP(callback, long, "", usage)
}

// CallbackVarP adds a Callback flag with a shortname and longname
func (flagSet *FlagSet) CallbackVarP(callback CallBackFunc, long, short string, usage string) *FlagData {
	if callback == nil {
		panic(fmt.Errorf("callback cannot be nil for flag -%v", long))
	}
	flagData := &FlagData{
		usage:        usage,
		long:         long,
		defaultValue: strconv.FormatBool(false),
		field:        &callBackVar{Value: callback},
		skipMarshal: true,
	}
	if short != "" {
		flagData.short = short
		flagSet.CommandLine.Var(flagData.field, short, usage)
		flagSet.flagKeys.Set(short, flagData)
	}
	flagSet.CommandLine.Var(flagData.field, long, usage)
	flagSet.flagKeys.Set(long, flagData)
	return flagData
}
