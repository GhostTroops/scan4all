package dnsxx

import (
	"github.com/hktalent/ProScan4all/lib/util"
	"testing"
)

func TestDoGetDnsInfos(t *testing.T) {
	util.SzPwd = "../.."
	util.InitDb()
	type args struct {
		t string
	}
	tests := []struct {
		name string
		args args
	}{
		{"test dnsx", args{"www.sina.com.cn"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := DoGetDnsInfos(tt.args.t)
			if nil != a && 0 < len(*a) {
				t.Logf("test ok: %+v", *a)
			} else {
				t.Fatalf("test not ok")
			}
		})
	}
}
