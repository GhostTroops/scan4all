package naabu

import "testing"

func TestDoNaabu(t *testing.T) {
	type args struct {
		target []string
	}
	tests := []struct {
		name string
		args args
	}{
		{"test naabu", args{[]string{"www.sina.com.cn"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DoNaabu(nil)
		})
	}
}
