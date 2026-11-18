package fileutil

import (
	"bufio"
	"io"
	"iter"
	"os"
	"strings"
)

// LineOption configures line reading.
type LineOption func(*lineConfig)

type lineConfig struct {
	bufferSize int
	splitSet   string
	hasSplit   bool
	trimSpace  bool
	skipEmpty  bool
	filter     func(string) bool
	comment    string
}

// WithBufferSize sets the underlying bufio.Scanner buffer. A non-positive
// value leaves the scanner default (64 KiB) in place.
func WithBufferSize(n int) LineOption {
	return func(c *lineConfig) { c.bufferSize = n }
}

// WithSplit splits each scanned line on any of the given runes
// (strings.FieldsFunc semantics: runs of separator runes are collapsed and
// empty pieces are not produced). Each piece becomes its own emitted value.
func WithSplit(separators ...rune) LineOption {
	return func(c *lineConfig) {
		c.hasSplit = true
		c.splitSet = string(separators)
	}
}

// WithTrimSpace trims leading/trailing whitespace from each emitted value.
func WithTrimSpace() LineOption {
	return func(c *lineConfig) { c.trimSpace = true }
}

// WithSkipEmpty drops empty values, evaluated after WithTrimSpace.
func WithSkipEmpty() LineOption {
	return func(c *lineConfig) { c.skipEmpty = true }
}

// WithFilter keeps only values for which keep returns true. The filter runs
// after split / trim / skip-empty so it sees the final value that would be
// yielded.
func WithFilter(keep func(string) bool) LineOption {
	return func(c *lineConfig) { c.filter = keep }
}

// Lines streams lines from the file at filename, applying any configured
// transforms. With no options it emits raw scanner lines.
//
// The file is opened lazily on first iteration and closed when iteration
// ends (including via break). Open and scanner errors are surfaced as a
// final ("", err) pair, after which iteration stops.
//
// Typical use:
//
//	for v, err := range fileutil.Lines(path,
//	    fileutil.WithSplit(','),
//	    fileutil.WithTrimSpace(),
//	    fileutil.WithSkipEmpty(),
//	) {
//	    if err != nil { return err }
//	    // use v
//	}
func Lines(filename string, opts ...LineOption) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		f, err := os.Open(filename)
		if err != nil {
			yield("", err)
			return
		}
		defer func() { _ = f.Close() }()
		scanLines(f, opts, yield)
	}
}

// LinesReader is the io.Reader variant of Lines. The reader is consumed but
// not closed; the caller owns its lifecycle.
func LinesReader(r io.Reader, opts ...LineOption) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		scanLines(r, opts, yield)
	}
}

func scanLines(r io.Reader, opts []LineOption, yield func(string, error) bool) {
	var cfg lineConfig
	for _, o := range opts {
		o(&cfg)
	}
	scanner := bufio.NewScanner(r)
	if cfg.bufferSize > 0 {
		scanner.Buffer(make([]byte, cfg.bufferSize), cfg.bufferSize)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if isComment(line, cfg.comment) {
			continue
		}
		if !cfg.hasSplit {
			if !emitLine(line, &cfg, yield) {
				return
			}
			continue
		}
		for _, piece := range strings.FieldsFunc(line, func(r rune) bool {
			return strings.ContainsRune(cfg.splitSet, r)
		}) {
			if !emitLine(piece, &cfg, yield) {
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		yield("", err)
	}
}

// isComment reports whether line should be skipped for prefix. An empty
// prefix skips nothing. Leading whitespace is ignored, and the check happens
// before split and trim so the rest of the line is dropped with it.
func isComment(line, prefix string) bool {
	return prefix != "" && strings.HasPrefix(strings.TrimSpace(line), prefix)
}

func emitLine(v string, cfg *lineConfig, yield func(string, error) bool) bool {
	if cfg.trimSpace {
		v = strings.TrimSpace(v)
	}
	if cfg.skipEmpty && v == "" {
		return true
	}
	if cfg.filter != nil && !cfg.filter(v) {
		return true
	}
	return yield(v, nil)
}
