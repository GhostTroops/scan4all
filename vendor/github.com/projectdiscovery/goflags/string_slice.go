package goflags

// StringSlice is a slice of strings
type StringSlice []string

// Set appends a value to the string slice.
func (stringSlice *StringSlice) Set(value string) error {
	*stringSlice = append(*stringSlice, value)
	return nil
}

func (stringSlice StringSlice) String() string {
	return ToString(stringSlice)
}
