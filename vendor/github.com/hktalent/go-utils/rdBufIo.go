package go_utils

import (
	"bufio"
	"io"
)

func DoRead4Line(r io.ReadCloser, doLine func(s string)) {
	buf := bufio.NewScanner(bufio.NewReaderSize(r, 1073741824000))
	defer r.Close()
	for buf.Scan() {
		doLine(buf.Text())
	}
}
