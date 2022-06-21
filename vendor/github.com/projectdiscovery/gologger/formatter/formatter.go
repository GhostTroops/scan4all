package formatter

import "github.com/projectdiscovery/gologger/levels"

// Formatter type format raw logging data into something useful
type Formatter interface {
	// Format formats the log event data into bytes
	Format(event *LogEvent) ([]byte, error)
}

// LogEvent is the respresentation of a single event to be logged.
type LogEvent struct {
	Message  string
	Level    levels.Level
	Metadata map[string]string
}
