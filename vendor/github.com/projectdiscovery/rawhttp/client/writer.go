package client

import (
	"bufio"
	"fmt"
	"io"
	"net/http/httputil"
	"strings"
)

type phase int

const (
	requestline phase = iota
	header
	body
)

func (p phase) String() string {
	switch p {
	case requestline:
		return "requestline"
	case header:
		return "headers"
	case body:
		return "body"
	default:
		return "UNKNOWN"
	}
}

type phaseError struct {
	expected, got phase
}

func (p *phaseError) Error() string {
	return fmt.Sprintf("phase error: expected %s, got %s", p.expected, p.got)
}

type writer struct {
	phase
	io.Writer
	tmp io.Writer // used to hold the original writer during the headers phase.
}

// StartHeaders moves the Conn into the headers phase
func (w *writer) StartHeaders() { w.phase = header }

// WriteRequestLine writes the RequestLine and moves the Conn to the headers phase
func (w *writer) WriteRequestLine(method, path string, query []string, version string) error {
	if w.phase != requestline {
		return &phaseError{requestline, w.phase}
	}
	q := strings.Join(query, "&")
	if len(q) > 0 {
		q = "?" + q
	}
	w.tmp, w.Writer = w.Writer, bufio.NewWriter(w.Writer)
	_, err := fmt.Fprintf(w, "%s %s%s %s\r\n", method, path, q, version)
	w.StartHeaders()
	return err
}

// WriteHeader writes the canonical header form to the wire.
func (w *writer) WriteHeader(key, value string) error {
	if w.phase != header {
		return &phaseError{header, w.phase}
	}
	var err error
	if value != "" {
		_, err = fmt.Fprintf(w, "%s: %s\r\n", key, value)
	} else {
		_, err = fmt.Fprintf(w, "%s\r\n", key)
	}

	return err
}

// StartBody moves the Conn into the body phase, no further headers may be sent at this point.
func (w *writer) StartBody() error {
	if _, err := w.Write([]byte(NewLine)); err != nil {
		return err
	}
	err := w.Writer.(*bufio.Writer).Flush()
	w.Writer, w.tmp = w.tmp, nil
	w.phase = body
	return err
}

// WriteBody writes the contents of r to the wire.
func (w *writer) WriteBody(r io.Reader) error {
	if w.phase != body {
		return &phaseError{body, w.phase}
	}
	_, err := io.Copy(w, r)
	w.phase = requestline
	return err
}

// WriteChunked writes the contents of r in chunked format to the wire.
func (w *writer) WriteChunked(r io.Reader) error {
	if w.phase != body {
		return &phaseError{body, w.phase}
	}
	cw := httputil.NewChunkedWriter(w)
	if _, err := io.Copy(cw, r); err != nil {
		return nil
	}
	w.phase = requestline
	return cw.Close()
}
