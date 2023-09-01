package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
)

type reader struct {
	*bufio.Reader
}

// ReadVersion reads a HTTP version string from the wire.
func (r *reader) ReadVersion() (Version, error) {
	var major, minor int
	for pos := 0; pos < len("HTTP/x.x "); pos++ {
		c, err := r.ReadByte()
		if err != nil {
			return invalidVersion, err
		}
		switch pos {
		case 0:
			if c != 'H' {
				return readVersionErr(pos, 'H', c)
			}
		case 1, 2:
			if c != 'T' {
				return readVersionErr(pos, 'T', c)
			}
		case 3:
			if c != 'P' {
				return readVersionErr(pos, 'P', c)
			}
		case 4:
			if c != '/' {
				return readVersionErr(pos, '/', c)
			}
		case 5:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				major = int(int(c) - 0x30)
			}
		case 6:
			if c != '.' {
				return readVersionErr(pos, '.', c)
			}
		case 7:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				minor = int(int(c) - 0x30)
			}
		case 8:
			if c != ' ' {
				return readVersionErr(pos, ' ', c)
			}
		}
	}
	return Version{Major: major, Minor: minor}, nil
}

var invalidVersion Version

func readVersionErr(pos int, expected, got byte) (Version, error) {
	return invalidVersion, fmt.Errorf("ReadVersion: expected %q, got %q at position %v", expected, got, pos)
}

const maxStatusCodeLength = 25

// ReadStatusCode reads the HTTP status code from the wire.
// - numbers of arbitrary size are accepted
// - non rfc status codes are supported
func (r *reader) ReadStatusCode() (int, error) {
	var pattern string
	// read until: space, \r
	for p := 0; p < maxStatusCodeLength; p++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if c == ' ' || c == '\r' {
			break
		}
		pattern += string(c)
	}
	return strconv.Atoi(pattern)
}

// ReadStatusLine reads the status line.
func (r *reader) ReadStatusLine() (Version, int, string, error) {
	version, err := r.ReadVersion()
	if err != nil {
		return Version{}, 0, "", err
	}
	code, err := r.ReadStatusCode()
	if err != nil {
		return Version{}, 0, "", err
	}
	msg, _, err := r.ReadLine()
	return version, code, string(msg), err
}

// ReadHeader reads a http header.
func (r *reader) ReadHeader() (string, string, bool, error) {
	line, err := r.readLine()
	if err != nil {
		return "", "", false, err
	}
	if line := string(line); line == "\r\n" || line == "\n" {
		return "", "", true, nil
	}
	v := bytes.SplitN(line, []byte(":"), 2)
	if len(v) != 2 {
		return "", "", false, fmt.Errorf("invalid header line: %q", line)
	}
	return string(bytes.TrimSpace(v[0])), string(bytes.TrimSpace(v[1])), false, nil
}

func (r *reader) ReadBody() io.Reader {
	return r
}

// readLine returns a []byte terminated by a \r\n.
func (r *reader) readLine() ([]byte, error) {
	return r.ReadBytes('\n')
}
