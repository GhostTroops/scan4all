package tools

import (
	"testing"
)

func TestNuclei(t *testing.T) {
	
}

func TestGetInput(t *testing.T) {
	type args struct {
		s string
		n int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "domain", args: args{s: "https://www.crsec.com.cn/", n: 0}, want: "www.crsec.com.cn"},
		{name: "domain", args: args{s: "https://www.crsec.com.cn:559/", n: 0}, want: "www.crsec.com.cn:559"},
		{name: "domain", args: args{s: "https://www.crsec.com.cn/#sdfs", n: 1}, want: "https://www.crsec.com.cn/#sdfs"},
		{name: "domain", args: args{s: "https://www.crsec.com.cn:559/xx/xxd?d=8", n: 1}, want: "https://www.crsec.com.cn:559/xx/xxd?d=8"},
		{name: "domain", args: args{s: "https://www.sina.com.cn/xx/xxd?d=8", n: 2}, want: `8.45.176.230
8.45.176.232
8.45.176.232
8.45.176.227
8.45.176.227
8.45.176.231
8.45.176.231
8.45.176.229
8.45.176.229
8.45.176.228
8.45.176.228
8.45.176.225
8.45.176.225
8.45.176.226
8.45.176.226`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetInput(tt.args.s, tt.args.n); got != tt.want {
				t.Errorf("GetInput() = %v, want %v", got, tt.want)
			} else {
				//log.Println(got)
			}
		})
	}
}
