package nla_test

import (
	"encoding/hex"
	"testing"

	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/protocol/nla"
)

func TestNTOWFv2(t *testing.T) {
	res := hex.EncodeToString(nla.NTOWFv2("", "", ""))
	expected := "f4c1a15dd59d4da9bd595599220d971a"
	if res != expected {
		t.Error(res, "not equal to", expected)
	}

	res = hex.EncodeToString(nla.NTOWFv2("user", "pwd", "dom"))
	expected = "652feb8208b3a8a6264c9c5d5b820979"
	if res != expected {
		t.Error(res, "not equal to", expected)
	}
}

func TestRC4K(t *testing.T) {
	key, _ := hex.DecodeString("55638e834ce774c100637f197bc0683f")
	src, _ := hex.DecodeString("177d16086dd3f06fa8d594e3bad005b7")
	res := hex.EncodeToString(nla.RC4K(key, src))
	expected := "f5ab375222707a492bd5a90705d96d1d"
	if res != expected {
		t.Error(res, "not equal to", expected)
	}
}
