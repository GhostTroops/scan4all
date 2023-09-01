//go:build windows

package fdmax

// Get the current limits
func Get() (*Limits, error) {
	return nil, ErrUnsupportedPlatform
}

// Set new system limits
func Set(maxLimit uint64) error {
	return ErrUnsupportedPlatform
}
