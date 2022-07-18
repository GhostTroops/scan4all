package proto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// Reader reads sentences from a RouterOS device.
type Reader interface {
	ReadSentence() (*Sentence, error)
}

type reader struct {
	*bufio.Reader
}

// NewReader returns a new Reader to read from r.
func NewReader(r io.Reader) Reader {
	return &reader{bufio.NewReader(r)}
}

// ReadSentence reads a sentence.
func (r *reader) ReadSentence() (*Sentence, error) {
	sen := NewSentence()
	for {
		b, err := r.readWord()
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return sen, nil
		}
		// Ex.: !re, !done
		if sen.Word == "" {
			sen.Word = string(b)
			continue
		}
		// Command tag.
		if bytes.HasPrefix(b, []byte(".tag=")) {
			sen.Tag = string(b[5:])
			continue
		}
		// Ex.: =key=value, =key
		if bytes.HasPrefix(b, []byte("=")) {
			t := bytes.SplitN(b[1:], []byte("="), 2)
			if len(t) == 1 {
				t = append(t, []byte{})
			}
			p := Pair{string(t[0]), string(t[1])}
			sen.List = append(sen.List, p)
			sen.Map[p.Key] = p.Value
			continue
		}
		return nil, fmt.Errorf("invalid RouterOS sentence word: %#q", b)
	}
}

func (r *reader) readNumber(size int) (int64, error) {
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return -1, err
	}
	var num int64
	for _, ch := range b {
		num = num<<8 | int64(ch)
	}
	return num, nil
}

func (r *reader) readLength() (int64, error) {
	l, err := r.readNumber(1)
	if err != nil {
		return -1, err
	}
	var n int64
	switch {
	case l&0x80 == 0x00:
	case (l & 0xC0) == 0x80:
		n, err = r.readNumber(1)
		l = l & ^0xC0 << 8 | n
	case l&0xE0 == 0xC0:
		n, err = r.readNumber(2)
		l = l & ^0xE0 << 16 | n
	case l&0xF0 == 0xE0:
		n, err = r.readNumber(3)
		l = l & ^0xF0 << 24 | n
	case l&0xF8 == 0xF0:
		l, err = r.readNumber(4)
	}
	if err != nil {
		return -1, err
	}
	return l, nil
}

func (r *reader) readWord() ([]byte, error) {
	l, err := r.readLength()
	if err != nil {
		return nil, err
	}
	b := make([]byte, l)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
