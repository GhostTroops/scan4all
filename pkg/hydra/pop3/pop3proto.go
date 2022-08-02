package pop3

import (
	"bufio"
	"fmt"
	"io"
	_ "log"
	"net/textproto"
	"strings"
)

// A ResponseError describes a protocol violation such as an invalid response or a hung-up connection.
type ResponseError string

func (r ResponseError) Error() string {
	return string(r)
}

// A Conn represents a textual network protocol connection for POP3.
type Conn struct {
	Reader
	Writer
	conn io.ReadWriteCloser
}

// NewConn returns a new Conn using conn for I/O.
func NewConn(conn io.ReadWriteCloser) *Conn {
	return &Conn{
		Reader: Reader{R: textproto.NewReader(bufio.NewReader(conn))},
		Writer: Writer{W: bufio.NewWriter(conn)},
		conn:   conn,
	}
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// A Reader implements convenience methods
// for reading requests or responses from a text protocol network connection.
type Reader struct {
	R *textproto.Reader
}

// NewReader returns a new Reader reading from r.
func NewReader(r *bufio.Reader) *Reader {
	return &Reader{R: textproto.NewReader(r)}
}

// ReadLine reads a single line from r,
// eliding the final \n or \r\n from the returned string.
// This calls textproto.Reader.ReadLine simply.
func (r *Reader) ReadLine() (string, error) {
	return r.R.ReadLine()
	// for debug
	// l, err := r.R.ReadLine()
	// log.Printf("> %s\n", l)
	// return l, err
}

// ReadLines reads a multiline until the last line of the only period,
// and returns a each line at slice.
// it does not contain last period.
func (r *Reader) ReadLines() ([]string, error) {
	var lines []string
	var line string
	var err error

	for {
		line, err = r.R.ReadLine()

		if err != nil {
			return nil, err
		}

		if line == "." {
			return lines, nil
		}

		lines = append(lines, line)
	}
}

// ReadToPeriod reads a multiline until the last line of the only period,
// and returns as a string.
// it does not contain last period.
func (r *Reader) ReadToPeriod() (string, error) {
	lines, err := r.ReadLines()

	if err != nil {
		return "", err
	}

	return strings.Join(lines, "\r\n"), nil
}

// ReadResponse reads a single line from r,
// and parses reponse.
// if the response is -ERR or has some other errors,
// it returns error.
func (r *Reader) ReadResponse() (string, error) {
	line, err := r.ReadLine()

	if err != nil {
		return "", err
	}

	return r.parseResponse(line)
}

func (r *Reader) parseResponse(line string) (string, error) {
	s := strings.ToUpper(line)

	if s == "+OK" {
		return "", nil
	} else if strings.HasPrefix(s, "+OK ") {
		return line[4:], nil
	} else if s == "-ERR" {
		return "", ResponseError("")
	} else if strings.HasPrefix(s, "-ERR ") {
		return "", ResponseError(line[5:])
	} else {
		return "", ResponseError(fmt.Sprintf("unknown response: %s", line))
	}
}

var crnl = []byte{'\r', '\n'}

// A Writer implements convenience methods
// for writing requests or responses to a text protocol network connection.
type Writer struct {
	W *bufio.Writer
}

// NewWriter returns a new Writer writing to w.
func NewWriter(w *bufio.Writer) *Writer {
	return &Writer{W: w}
}

// WriteLine writes the formatted output followed by \r\n.
func (w *Writer) WriteLine(format string, args ...interface{}) error {
	var err error

	if _, err = fmt.Fprintf(w.W, format, args...); err != nil {
		return err
	}

	if _, err = w.W.Write(crnl); err != nil {
		return err
	}

	return w.W.Flush()

	// for debug
	// var err error

	// l := fmt.Sprintf(format, args...)

	// if _, err = fmt.Fprint(w.W, l); err != nil {
	// 	return err
	// }

	// if _, err = w.W.Write(crnl); err != nil {
	// 	return err
	// }

	// if err = w.W.Flush(); err != nil {
	// 	return err
	// }

	// log.Printf("< %s\n", l)

	// return nil
}
