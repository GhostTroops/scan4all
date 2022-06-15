package levels

// Level defines all the available levels we can log at
type Level int

// Available logging levels
const (
	LevelFatal Level = iota
	LevelSilent
	LevelError
	LevelInfo
	LevelWarning
	LevelDebug
	LevelVerbose
)

// String returns the string representation of a log level
func (l Level) String() string {
	return [...]string{"fatal", "silent", "error", "info", "warning", "debug", "verbose"}[l]
}
