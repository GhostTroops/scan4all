package reader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// ReusableReadCloser is a reusable reader with no-op close
type ReusableReadCloser struct {
	*sync.RWMutex
	io.Reader
	readBuf *bytes.Buffer
	backBuf *bytes.Buffer
}

// NewReusableReadCloser is returned for any type of input
func NewReusableReadCloser(raw interface{}) (*ReusableReadCloser, error) {
	readBuf := bytes.Buffer{}
	backBuf := bytes.Buffer{}
	if raw != nil {
		switch body := raw.(type) {

		case []byte:
			// copy: reset writes the buffer back, which must not reach the
			// caller's slice or another reader built from it
			readBuf = *bytes.NewBuffer(bytes.Clone(body))

		case *[]byte:
			if body != nil {
				readBuf = *bytes.NewBuffer(bytes.Clone(*body))
			}

		case string:
			// if a string , create buffer from string and use it
			readBuf = *bytes.NewBufferString(body)

		case *bytes.Buffer:
			// clone buffer's bytes to avoid sharing and mutating caller's memory
			if body != nil {
				readBuf = *bytes.NewBuffer(bytes.Clone(body.Bytes()))
			}

		case *bytes.Reader:
			// if *bytes.Reader , make buffer read from reader
			if _, er := readBuf.ReadFrom(body); er != nil {
				return nil, er
			}

		case *strings.Reader:
			// if *strings.Reader , make buffer read from reader
			if _, er := readBuf.ReadFrom(body); er != nil {
				return nil, er
			}

		case io.ReadSeeker:
			// if io.ReadSeeker , make buffer read from reader
			if _, er := readBuf.ReadFrom(body); er != nil {
				return nil, er
			}

		case io.Reader:
			// if io.Reader , make buffer read from reader
			if _, er := readBuf.ReadFrom(body); er != nil {
				return nil, er
			}
		default:
			// type not implemented or cannot handle
			return nil, fmt.Errorf("cannot handle type %T", body)
		}

	}
	reusableReadCloser := &ReusableReadCloser{
		&sync.RWMutex{},
		io.TeeReader(&readBuf, &backBuf),
		&readBuf,
		&backBuf,
	}

	return reusableReadCloser, nil

}

// Read []byte from Reader
func (r ReusableReadCloser) Read(p []byte) (int, error) {
	r.Lock()
	defer r.Unlock()

	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.reset()
	}
	return n, err
}

func (r ReusableReadCloser) reset() {
	_, _ = io.Copy(r.readBuf, r.backBuf)
}

// Close is a no-op close of ReusableReadCloser
func (r ReusableReadCloser) Close() error {
	return nil
}
