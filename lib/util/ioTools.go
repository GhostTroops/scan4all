package util

import (
	"bytes"
	"io"
)

func Bytes2Reader(data *[]byte) io.ReadCloser {
	return io.NopCloser(bytes.NewBuffer(*data))
}
