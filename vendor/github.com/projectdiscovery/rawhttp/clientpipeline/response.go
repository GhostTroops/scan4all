package clientpipeline

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"strconv"
	"strings"
)

// Response represents an RFC2616 response.
type Response struct {
	Version
	Status
	Headers []Header
	body    []byte
	Body    io.Reader
}

// ContentLength returns the length of the body. If the body length is not known
// ContentLength will return -1.
func (r *Response) ContentLength() int64 {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Content-Length") {
			length, err := strconv.ParseInt(h.Value, 10, 64)
			if err != nil {
				continue
			}
			return int64(length)
		}
	}
	return -1
}

// CloseRequested returns if Reason includes a Connection: close header.
func (r *Response) CloseRequested() bool {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Connection") {
			return h.Value == "close"
		}
	}
	return false
}

// TransferEncoding returns the transfer encoding this message was transmitted with.
// If not is specified by the sender, "identity" is assumed.
func (r *Response) TransferEncoding() string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Transfer-Encoding") {
			switch h.Value {
			case "identity", "chunked":
				return h.Value
			}
		}
	}
	return "identity"
}

// Status represents an HTTP status code.
type Status struct {
	Code   int
	Reason string
}

func (resp *Response) Read(r *bufio.Reader) error {
	version, code, msg, err := resp.ReadStatusLine(r)
	var headers []Header
	if err != nil {
		return fmt.Errorf("ReadStatusLine: %v", err)
	}
	for {
		var key, value string
		var done bool
		key, value, done, err = resp.ReadHeader(r)
		if err != nil || done {
			break
		}
		if key == "" {
			// empty header values are valid, rfc 2616 s4.2.
			err = errors.New("invalid header") //nolint
			break
		}
		headers = append(headers, Header{key, value})
	}

	resp.Version = version
	resp.Status = Status{Code: code, Reason: msg}
	resp.Headers = headers
	resp.Body = resp.ReadBody(r)

	if l := resp.ContentLength(); l >= 0 {
		resp.Body = io.LimitReader(resp.Body, l)
	} else if resp.TransferEncoding() == "chunked" {
		resp.Body = httputil.NewChunkedReader(resp.Body)
	}

	return nil
}

func (resp *Response) ReadVersion(r *bufio.Reader) (Version, error) {
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

// ReadStatusCode reads the HTTP status code from the wire.
func (resp *Response) ReadStatusCode(r *bufio.Reader) (int, error) {
	var code int
	for pos := 0; pos < len("200 "); pos++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		switch pos {
		case 0, 1, 2:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				switch pos {
				case 0:
					code = int(int(c)-0x30) * 100
				case 1:
					code += int(int(c)-0x30) * 10
				case 2:
					code += int(int(c) - 0x30)
				}
			}
		case 3:
			switch c {
			case '\r':
				// special case "HTTP/1.1 301\r\n" has a blank reason.
			case ' ':
				// nothing
			default:
				return 0, fmt.Errorf("ReadStatusCode: expected %q, got %q at position %v", ' ', c, pos)
			}
		}
	}
	return code, nil
}

// ReadStatusLine reads the status line.
func (resp *Response) ReadStatusLine(r *bufio.Reader) (Version, int, string, error) {
	version, err := resp.ReadVersion(r)
	if err != nil {
		return Version{}, 0, "", err
	}
	code, err := resp.ReadStatusCode(r)
	if err != nil {
		return Version{}, 0, "", err
	}
	msg, _, err := r.ReadLine()
	return version, code, string(msg), err
}

// ReadHeader reads a http header.
func (resp *Response) ReadHeader(r *bufio.Reader) (string, string, bool, error) {
	line, err := resp.readLine(r)
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

func (resp *Response) ReadBody(r *bufio.Reader) io.Reader {
	l := resp.ContentLength()
	if l > 0 {
		resp.body = make([]byte, l)
		io.ReadFull(r, resp.body) //nolint

		return bytes.NewReader(resp.body)
	}

	return r
}

// readLine returns a []byte terminated by a \r\n.
func (resp *Response) readLine(r *bufio.Reader) ([]byte, error) {
	return r.ReadBytes('\n')
}
