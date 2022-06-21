package core_test

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestWriteUInt16LE(t *testing.T) {
	buff := &bytes.Buffer{}
	WriteUInt32LE(66538, buff)
	result := hex.EncodeToString(buff.Bytes())
	expected := "ea030100"
	if result != expected {
		t.Error(result, "not equals to", expected)
	}
}
