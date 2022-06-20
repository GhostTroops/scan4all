package core_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/core"
)

func TestWriteUInt16LE(t *testing.T) {
	buff := &bytes.Buffer{}
	core.WriteUInt32LE(66538, buff)
	result := hex.EncodeToString(buff.Bytes())
	expected := "ea030100"
	if result != expected {
		t.Error(result, "not equals to", expected)
	}
}
