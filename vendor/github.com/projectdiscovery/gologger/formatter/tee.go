package formatter

import (
	"io"
)

// Tee formatter can be used to write the event to a writer while also use the existing formatter and output
type Tee struct {
	Wrapper Formatter
	w       io.Writer

	Formatter Formatter
}

// NewTee returns a new TeeWriter with default JSON messages
func NewTee(wrapper Formatter, w io.Writer) (teeW *Tee) {
	teeW = &Tee{
		Wrapper:   wrapper,
		Formatter: &JSON{},
	}
	teeW.w = w
	return
}

// Format saves the event and forwards the event to the internal Wrapper
func (tee *Tee) Format(event *LogEvent) (bts []byte, err error) {
	if event == nil {
		return
	}
	label := event.Metadata["label"]

	bts, err = tee.Formatter.Format(event)
	// the format delete the label key from Metadat - if we want colors we need to add it again
	if label != "" {
		event.Metadata["label"] = label
	}
	if err != nil {
		return
	}

	// ignore write error to prevent complete loss of data
	_, _ = tee.w.Write(append(bts, []byte("\n")...))

	return tee.Wrapper.Format(event)
}
