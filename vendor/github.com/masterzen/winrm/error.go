package winrm

// winrmError generic error struct
type winrmError struct {
	message string
}

// ErrWinrm implements the Error type interface
func (e winrmError) Error() string {
	return e.message
}
