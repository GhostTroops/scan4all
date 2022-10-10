package goflags

var optionMap map[*StringSlice]Options

func init() {
	optionMap = make(map[*StringSlice]Options)
}

// StringSlice is a slice of strings
type StringSlice []string

// Set appends a value to the string slice.
func (stringSlice *StringSlice) Set(value string) error {
	option, ok := optionMap[stringSlice]
	if !ok {
		option = StringSliceOptions
	}
	values, err := ToStringSlice(value, option)
	if err != nil {
		return err
	}
	*stringSlice = append(*stringSlice, values...)
	return nil
}

func (stringSlice StringSlice) String() string {
	return ToString(stringSlice)
}
