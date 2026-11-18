package gologger

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync/atomic"
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

// Logger is a logger for logging structured data in a beautiful and fast manner.
type Logger struct {
	writer            writer.Writer
	maxLevel          atomic.Int32 // stores levels.Level
	formatter         formatter.Formatter
	timestampMinLevel levels.Level
	timestamp         bool
	timestampFormat   string
	groupPrefix       string      // For slog group support
	persistedAttrs    []slog.Attr // For slog WithAttrs support
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
	l.maxLevel.Store(int32(level))
}

func (l *Logger) getMaxLevel() levels.Level {
	return levels.Level(l.maxLevel.Load())
}

// SetFormatter sets the formatter instance for a logger
func (l *Logger) SetFormatter(formatter formatter.Formatter) {
	l.formatter = formatter
}

// SetWriter sets the writer instance for a logger
func (l *Logger) SetWriter(writer writer.Writer) {
	l.writer = writer
}

// SetTimestamp enables/disables automatic or custom timestamp
func (l *Logger) SetTimestamp(timestamp bool, minLevel levels.Level) {
	l.SetTimestampWithFormat(timestamp, minLevel, time.RFC3339)
}

func (l *Logger) SetTimestampWithFormat(timestamp bool, minLevel levels.Level, format string) {
	l.timestamp = timestamp
	l.timestampMinLevel = minLevel
	if len(format) > 0 {
		l.timestampFormat = format
	}
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
	timestampFormat := time.RFC3339
	if e.logger.timestampFormat != "" {
		timestampFormat = e.logger.timestampFormat
	}
	e.metadata["timestamp"] = time.Now().Format(timestampFormat)
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

// Print prints a string without any extra labels.
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
	return e.level <= e.logger.getMaxLevel()
}

// formatAttrValue converts slog.Value to string representation appropriate for gologger metadata
func formatAttrValue(v slog.Value) (result string) {
	// Add panic recovery to prevent crashes from malformed values
	defer func() {
		if r := recover(); r != nil {
			// If formatting panics, return a safe fallback
			// This could happen with malformed time values, nil pointers, etc.
			result = fmt.Sprintf("<error formatting value: %v>", r)
		}
	}()

	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return fmt.Sprintf("%d", v.Int64())
	case slog.KindUint64:
		return fmt.Sprintf("%d", v.Uint64())
	case slog.KindFloat64:
		f := v.Float64()
		// Handle special float values gracefully
		if math.IsNaN(f) {
			return "NaN"
		} else if math.IsInf(f, 1) {
			return "+Inf"
		} else if math.IsInf(f, -1) {
			return "-Inf"
		}
		return fmt.Sprintf("%g", f)
	case slog.KindBool:
		if v.Bool() {
			return "true"
		}
		return "false"
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		t := v.Time()
		if t.IsZero() {
			return "0001-01-01T00:00:00Z"
		}
		return t.Format(time.RFC3339)
	case slog.KindAny:
		any := v.Any()
		if any == nil {
			return "<nil>"
		}
		// Use safe formatting that won't panic on circular references
		return fmt.Sprintf("%+v", any)
	case slog.KindGroup:
		// Groups should be handled at a higher level by flattening keys
		// This shouldn't normally be reached as groups are processed differently
		return fmt.Sprintf("[group:%s]", v.String())
	default:
		// Fallback for unknown kinds or future slog extensions
		return v.String()
	}
}

// Custom slog levels that match gologger's level hierarchy.
// These can be used with any slog handler.
const (
	LevelTrace   = slog.Level(-8) // Most detailed logging (DEBUG-4)
	LevelVerbose = slog.Level(-6) // More detailed than debug (DEBUG-2)
	LevelSilent  = slog.Level(1)  // No label output (INFO+1)
	LevelFatal   = slog.Level(12) // Critical errors causing exit (ERROR+4)
)

// slogLevelToGologgerLevel converts slog.Level to gologger levels.Level
func slogLevelToGologgerLevel(level slog.Level) levels.Level {
	switch {
	case level >= LevelFatal:
		return levels.LevelFatal
	case level >= slog.LevelError:
		return levels.LevelError
	case level >= slog.LevelWarn:
		return levels.LevelWarning
	case level >= LevelSilent:
		return levels.LevelSilent
	case level >= slog.LevelInfo:
		return levels.LevelInfo
	case level >= slog.LevelDebug:
		return levels.LevelDebug
	case level >= LevelVerbose:
		return levels.LevelVerbose
	case level >= LevelTrace:
		return levels.LevelVerbose // Map trace to verbose level
	default:
		return levels.LevelVerbose
	}
}

// // gologgerLevelToSlogLevel converts gologger levels.Level to slog.Level
// func gologgerLevelToSlogLevel(level levels.Level) slog.Level {
// 	switch level {
// 	case levels.LevelFatal:
// 		return LevelFatal
// 	case levels.LevelError:
// 		return slog.LevelError
// 	case levels.LevelWarning:
// 		return slog.LevelWarn
// 	case levels.LevelInfo:
// 		return slog.LevelInfo
// 	case levels.LevelSilent:
// 		return LevelSilent
// 	case levels.LevelDebug:
// 		return slog.LevelDebug
// 	case levels.LevelVerbose:
// 		return LevelVerbose
// 	default:
// 		return slog.LevelInfo
// 	}
// }

// Enabled implements slog.Handler interface
func (l *Logger) Enabled(_ context.Context, level slog.Level) bool {
	gologgerLevel := slogLevelToGologgerLevel(level)
	return gologgerLevel <= l.getMaxLevel()
}

// Handle implements slog.Handler interface
func (l *Logger) Handle(ctx context.Context, record slog.Record) error {
	// Check if context is cancelled before proceeding
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	gologgerLevel := slogLevelToGologgerLevel(record.Level)

	event := &Event{
		logger:   l,
		level:    gologgerLevel,
		message:  record.Message,
		metadata: make(map[string]string),
	}

	// Add timestamp if enabled
	if l.timestamp && gologgerLevel >= l.timestampMinLevel {
		event.TimeStamp()
	}

	// Set level metadata - but skip for Silent level (Print/Silent should have no labels)
	if gologgerLevel != levels.LevelSilent {
		if label, ok := labels[gologgerLevel]; ok {
			event.metadata["label"] = label
		}
	}

	// Add persisted attributes (from WithAttrs)
	for _, attr := range l.persistedAttrs {
		key := l.groupPrefix + attr.Key
		event.metadata[key] = formatAttrValue(attr.Value)
	}

	// Add attributes from current record
	record.Attrs(func(attr slog.Attr) bool {
		key := l.groupPrefix + attr.Key
		event.metadata[key] = formatAttrValue(attr.Value)
		return true
	})

	l.Log(event)
	return nil
}

// WithAttrs implements slog.Handler interface
func (l *Logger) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Create a new logger instance with same settings and persisted attributes
	persistedAttrs := make([]slog.Attr, len(l.persistedAttrs)+len(attrs))
	copy(persistedAttrs, l.persistedAttrs)
	copy(persistedAttrs[len(l.persistedAttrs):], attrs)

	child := &Logger{
		writer:            l.writer,
		formatter:         l.formatter,
		timestampMinLevel: l.timestampMinLevel,
		timestamp:         l.timestamp,
		timestampFormat:   l.timestampFormat,
		groupPrefix:       l.groupPrefix,
		persistedAttrs:    persistedAttrs,
	}
	child.maxLevel.Store(l.maxLevel.Load())
	return child
}

// WithGroup implements slog.Handler interface.
// Per the slog.Handler contract, an empty name returns the receiver unchanged.
func (l *Logger) WithGroup(name string) slog.Handler {
	if name == "" {
		return l
	}

	var newPrefix string
	if l.groupPrefix == "" {
		newPrefix = name + "."
	} else {
		newPrefix = l.groupPrefix + name + "."
	}

	child := &Logger{
		writer:            l.writer,
		formatter:         l.formatter,
		timestampMinLevel: l.timestampMinLevel,
		timestamp:         l.timestamp,
		timestampFormat:   l.timestampFormat,
		groupPrefix:       newPrefix,
		persistedAttrs:    l.persistedAttrs,
	}
	child.maxLevel.Store(l.maxLevel.Load())
	return child
}

// TrimGologgerLevels creates handler options that convert gologger offset levels to clean names
// e.g., "DEBUG-4" becomes "TRACE", "ERROR+4" becomes "FATAL", "INFO+1" becomes "" (silent)
func TrimGologgerLevels() *slog.HandlerOptions {
	return &slog.HandlerOptions{
		Level: LevelTrace, // Enable all custom levels
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				if level, ok := a.Value.Any().(slog.Level); ok {
					cleanLevel := cleanLevelString(level)
					if cleanLevel == "" {
						// For silent level, return empty attr to remove level entirely
						return slog.Attr{}
					}
					return slog.String(slog.LevelKey, cleanLevel)
				}
			}
			return a
		},
	}
}

// cleanLevelString converts gologger custom levels to clean names
func cleanLevelString(level slog.Level) string {
	switch level {
	case LevelTrace:
		return "TRACE"
	case LevelVerbose:
		return "VERBOSE"
	case LevelSilent:
		return "" // Silent = no level label
	case LevelFatal:
		return "FATAL"
	default:
		// For standard levels, return the standard string
		return level.String()
	}
}
