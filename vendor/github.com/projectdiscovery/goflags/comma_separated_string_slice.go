package goflags

// CommaSeparatedStringSlice is a slice of strings
type CommaSeparatedStringSlice []string

// Set appends a value to the string slice.
func (commaSeparatedStringSlice *CommaSeparatedStringSlice) Set(value string) error {
	slice, err := ToCommaSeparatedStringSlice(value)
	if err != nil {
		return err
	}
	*commaSeparatedStringSlice = append(*commaSeparatedStringSlice, slice...)
	return nil
}

func (commaSeparatedStringSlice CommaSeparatedStringSlice) String() string {
	return ToString(commaSeparatedStringSlice)
}

func ToCommaSeparatedStringSlice(value string) ([]string, error) {
	return toStringSlice(value, DefaultCommaSeparatedStringSliceOptions)
}

var DefaultCommaSeparatedStringSliceOptions = Options{
	IsEmpty: isEmpty,
}

// FileCommaSeparatedStringSlice is a slice of strings
type FileCommaSeparatedStringSlice []string

// Set appends a value to the string slice.
func (fileCommaSeparatedStringSlice *FileCommaSeparatedStringSlice) Set(value string) error {
	slice, err := ToFileCommaSeparatedStringSlice(value)
	if err != nil {
		return err
	}
	*fileCommaSeparatedStringSlice = append(*fileCommaSeparatedStringSlice, slice...)
	return nil
}

func (fileCommaSeparatedStringSlice FileCommaSeparatedStringSlice) String() string {
	return ToString(fileCommaSeparatedStringSlice)
}

var DefaultFileCommaSeparatedStringSliceOptions = Options{
	IsEmpty:    isEmpty,
	IsFromFile: func(s string) bool { return true },
}

func ToFileCommaSeparatedStringSlice(value string) ([]string, error) {
	return toStringSlice(value, DefaultFileCommaSeparatedStringSliceOptions)
}
