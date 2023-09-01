package goflags

import (
	"fmt"
	"strconv"

	fileutil "github.com/projectdiscovery/utils/file"
)

type Size int

func (s *Size) Set(size string) error {
	sizeInBytes, err := fileutil.FileSizeToByteLen(size)
	if err != nil {
		return err
	}
	*s = Size(sizeInBytes)
	return nil
}

func (s *Size) String() string {
	return strconv.Itoa(int(*s))
}

// SizeVar converts the given fileSize with a unit (kb, mb, gb, or tb) to bytes.
// For example, '2kb' will be converted to 2048.
// If no unit is provided, it will fallback to mb. e.g: '2' will be converted to 2097152.
func (flagSet *FlagSet) SizeVar(field *Size, long string, defaultValue string, usage string) *FlagData {
	return flagSet.SizeVarP(field, long, "", defaultValue, usage)
}

// SizeVarP converts the given fileSize with a unit (kb, mb, gb, or tb) to bytes.
// For example, '2kb' will be converted to 2048.
// If no unit is provided, it will fallback to mb. e.g: '2' will be converted to 2097152.
func (flagSet *FlagSet) SizeVarP(field *Size, long, short string, defaultValue string, usage string) *FlagData {
	if field == nil {
		panic(fmt.Errorf("field cannot be nil for flag -%v", long))
	}
	if defaultValue != "" {
		if err := field.Set(defaultValue); err != nil {
			panic(fmt.Errorf("failed to set default value for flag -%v: %v", long, err))
		}
	}
	flagData := &FlagData{
		usage:        usage,
		long:         long,
		defaultValue: defaultValue,
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
