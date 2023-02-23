package gologger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
)

var (
	labels = map[levels.Level]string{
		levels.LevelFatal:   "FTL",
		levels.LevelError:   "ERR",
		levels.LevelInfo:    "INF",
		levels.LevelWarning: "WRN",
		levels.LevelDebug:   "DBG",
		levels.LevelVerbose: "VER",
	}
	// DefaultLogger is the default logging instance
	DefaultLogger *Logger
)

func init() {
	DefaultLogger = &Logger{}
	DefaultLogger.SetMaxLevel(levels.LevelInfo)
	DefaultLogger.SetFormatter(formatter.NewCLI(false))
	DefaultLogger.SetWriter(writer.NewCLI())
}

// Logger is a logger for logging structured data in a beautfiul and fast manner.
type Logger struct {
	writer            writer.Writer
	maxLevel          levels.Level
	formatter         formatter.Formatter
	timestampMinLevel levels.Level
	timestamp         bool
}

// Log logs a message to a logger instance
func (l *Logger) Log(event *Event) {
	if !isCurrentLevelEnabled(event) {
		return
	}
	event.message = strings.TrimSuffix(event.message, "\n")
	data, err := l.formatter.Format(&formatter.LogEvent{
		Message:  event.message,
		Level:    event.level,
		Metadata: event.metadata,
	})
	if err != nil {
		return
	}
	l.writer.Write(data, event.level)

	if event.level == levels.LevelFatal {
		os.Exit(1)
	}
}

// SetMaxLevel sets the max logging level for logger
func (l *Logger) SetMaxLevel(level levels.Level) {
	l.maxLevel = level
}

// SetFormatter sets the formatter instance for a logger
func (l *Logger) SetFormatter(formatter formatter.Formatter) {
	l.formatter = formatter
}

// SetWriter sets the writer instance for a logger
func (l *Logger) SetWriter(writer writer.Writer) {
	l.writer = writer
}

// SetTimestamp enables/disables automatic timestamp
func (l *Logger) SetTimestamp(timestamp bool, minLevel levels.Level) {
	l.timestamp = timestamp
	l.timestampMinLevel = minLevel
}

// Event is a log event to be written with data
type Event struct {
	logger   *Logger
	level    levels.Level
	message  string
	metadata map[string]string
}

func newDefaultEventWithLevel(level levels.Level) *Event {
	return newEventWithLevelAndLogger(level, DefaultLogger)
}

func newEventWithLevelAndLogger(level levels.Level, l *Logger) *Event {
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	if l.timestamp && level >= l.timestampMinLevel {
		event.TimeStamp()
	}
	return event
}

func (e *Event) setLevelMetadata(level levels.Level) {
	e.metadata["label"] = labels[level]
}

// Label applies a custom label on the log event
func (e *Event) Label(label string) *Event {
	e.metadata["label"] = label
	return e
}

// TimeStamp adds timestamp to the log event
func (e *Event) TimeStamp() *Event {
	e.metadata["timestamp"] = time.Now().Format(time.RFC3339)
	return e
}

// Str adds a string metadata item to the log
func (e *Event) Str(key, value string) *Event {
	e.metadata[key] = value
	return e
}

// Msg logs a message to the logger
func (e *Event) Msg(message string) {
	e.message = message
	e.logger.Log(e)
}

// Msgf logs a printf style message to the logger
func (e *Event) Msgf(format string, args ...interface{}) {
	e.message = fmt.Sprintf(format, args...)
	e.logger.Log(e)
}

// MsgFunc logs a message with lazy evaluation.
// Useful when computing the message can be resource heavy.
func (e *Event) MsgFunc(messageSupplier func() string) {
	if !isCurrentLevelEnabled(e) {
		return
	}
	e.message = messageSupplier()
	e.logger.Log(e)
}

// Info writes a info message on the screen with the default label
func Info() *Event {
	event := newDefaultEventWithLevel(levels.LevelInfo)
	event.setLevelMetadata(levels.LevelInfo)
	return event
}

// Warning writes a warning message on the screen with the default label
func Warning() *Event {
	event := newDefaultEventWithLevel(levels.LevelWarning)
	event.setLevelMetadata(levels.LevelWarning)
	return event
}

// Error writes a error message on the screen with the default label
func Error() *Event {
	event := newDefaultEventWithLevel(levels.LevelError)
	event.setLevelMetadata(levels.LevelError)
	return event
}

// Debug writes an error message on the screen with the default label
func Debug() *Event {
	event := newDefaultEventWithLevel(levels.LevelDebug)
	event.setLevelMetadata(levels.LevelDebug)
	return event
}

// Fatal exits the program if we encounter a fatal error
func Fatal() *Event {
	event := newDefaultEventWithLevel(levels.LevelFatal)
	event.setLevelMetadata(levels.LevelFatal)
	return event
}

// Silent prints a string on stdout without any extra labels.
func Silent() *Event {
	event := newDefaultEventWithLevel(levels.LevelSilent)
	return event
}

// Print prints a string on stderr without any extra labels.
func Print() *Event {
	event := newDefaultEventWithLevel(levels.LevelInfo)
	return event
}

// Verbose prints a string only in verbose output mode.
func Verbose() *Event {
	event := newDefaultEventWithLevel(levels.LevelVerbose)
	event.setLevelMetadata(levels.LevelVerbose)
	return event
}

// Info writes a info message on the screen with the default label
func (l *Logger) Info() *Event {
	event := newEventWithLevelAndLogger(levels.LevelInfo, l)
	event.setLevelMetadata(levels.LevelInfo)
	return event
}

// Warning writes a warning message on the screen with the default label
func (l *Logger) Warning() *Event {
	event := newEventWithLevelAndLogger(levels.LevelWarning, l)
	event.setLevelMetadata(levels.LevelWarning)
	return event
}

// Error writes a error message on the screen with the default label
func (l *Logger) Error() *Event {
	event := newEventWithLevelAndLogger(levels.LevelError, l)
	event.setLevelMetadata(levels.LevelError)
	return event
}

// Debug writes an error message on the screen with the default label
func (l *Logger) Debug() *Event {
	event := newEventWithLevelAndLogger(levels.LevelDebug, l)
	event.setLevelMetadata(levels.LevelDebug)
	return event
}

// Fatal exits the program if we encounter a fatal error
func (l *Logger) Fatal() *Event {
	event := newEventWithLevelAndLogger(levels.LevelFatal, l)
	event.setLevelMetadata(levels.LevelFatal)
	return event
}

// Print prints a string on screen without any extra labels.
func (l *Logger) Print() *Event {
	event := newEventWithLevelAndLogger(levels.LevelSilent, l)
	return event
}

// Verbose prints a string only in verbose output mode.
func (l *Logger) Verbose() *Event {
	event := newEventWithLevelAndLogger(levels.LevelVerbose, l)
	event.setLevelMetadata(levels.LevelVerbose)
	return event
}

func isCurrentLevelEnabled(e *Event) bool {
	return e.level <= e.logger.maxLevel
}
