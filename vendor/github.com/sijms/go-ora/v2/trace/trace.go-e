package trace

import (
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// Tracer is the interface for a Tracer. It is implemented as
// a full tracer : traceWriter
// a no-tracer: nilTracer
type Tracer interface {
	Close() error                      // To close file
	Print(vs ...interface{})           // like fmt.Print(a,b,c ...)
	Printf(f string, s ...interface{}) // like fmt.Printf("%d: %s",1254,"Hello")
	LogPacket(s string, p []byte)      // to dump packet like hexdump -C f
	IsOn() bool                        // To check if trace is enabled
}

type traceWriter struct {
	w io.WriteCloser
}

// NewTraceWriter return a tracer that will write the trace into w
func NewTraceWriter(w io.WriteCloser) *traceWriter {
	return &traceWriter{w}
}

func (t *traceWriter) Close() (err error) {
	if t.w != nil {
		err = t.w.Close()
	}
	return
}
func (t traceWriter) IsOn() bool { return true }

func (t traceWriter) Print(vs ...interface{}) {
	if t.w == nil {
		return
	}
	t.w.Write([]byte(fmt.Sprintf("%s: ", time.Now().Format("2006-01-02T15:04:05.0000"))))
	for _, v := range vs {
		t.w.Write([]byte(fmt.Sprintf("%v", v)))
	}
	t.w.Write([]byte{'\n'})
}

func (t traceWriter) Printf(f string, s ...interface{}) {
	if t.w != nil {
		t.Print(fmt.Sprintf(f, s...))
	}
}

func (t traceWriter) LogPacket(s string, p []byte) {
	if t.w == nil {
		return
	}
	t.Print("\n", s)
	t.w.Write([]byte(hex.Dump(p)))
}

type nilTracer struct{}

// NilTracer instantiate a no-tracer
func NilTracer() *nilTracer                         { return &nilTracer{} }
func (nilTracer) IsOn() bool                        { return false }
func (nilTracer) Close() error                      { return nil }
func (nilTracer) Print(vs ...interface{})           {}
func (nilTracer) Printf(f string, s ...interface{}) {}
func (nilTracer) LogPacket(s string, p []byte)      {}
