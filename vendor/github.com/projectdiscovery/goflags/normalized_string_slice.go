package goflags

// NormalizedStringSlice is a slice of strings
type NormalizedStringSlice []string

// Set appends a value to the string slice.
func (normalizedStringSlice *NormalizedStringSlice) Set(value string) error {
	slice, err := ToNormalizedStringSlice(value)
	if err != nil {
		return err
	}
	*normalizedStringSlice = append(*normalizedStringSlice, slice...)
	return nil
}

func (normalizedStringSlice NormalizedStringSlice) String() string {
	return ToString(normalizedStringSlice)
}

func ToNormalizedStringSlice(value string) ([]string, error) {
	return toStringSlice(value, DefaultNormalizedStringSliceOptions)
}

var DefaultNormalizedStringSliceOptions = Options{
	IsEmpty:   isEmpty,
	Normalize: normalizeLowercase,
}

// NormalizedOriginalStringSlice is a slice of strings
type NormalizedOriginalStringSlice []string

// Set appends a value to the string slice.
func (normalizedStringSlice *NormalizedOriginalStringSlice) Set(value string) error {
	slice, err := ToNormalizedOriginalStringSlice(value)
	if err != nil {
		return err
	}
	*normalizedStringSlice = append(*normalizedStringSlice, slice...)
	return nil
}

func (normalizedStringSlice NormalizedOriginalStringSlice) String() string {
	return ToString(normalizedStringSlice)
}

func ToNormalizedOriginalStringSlice(value string) ([]string, error) {
	return toStringSlice(value, DefaultNormalizedOriginalStringSliceOptions)
}

var DefaultNormalizedOriginalStringSliceOptions = Options{
	IsEmpty:   isEmpty,
	Normalize: normalize,
}
