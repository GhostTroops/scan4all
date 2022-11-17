package main

import (
	"github.com/hktalent/ProScan4all/pkg/xcmd"
	util "github.com/hktalent/go-utils"
	"testing"
)

func TestDoAmass(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"amass", args{"www.sina.com.cn\nhttps://www.baidu.com:443\n*.**.163.com"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoAmass(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoSubfinder(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"subfinder", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoSubfinder(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoShuffledns(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"shuffledns", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoShuffledns(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoKatana(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"Katana", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoKatana(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoTlsx(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"tlsx", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoTlsx(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoDnsx(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"dnsx", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoDnsx(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoNuclei(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"nuclei", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoNuclei(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoHttpx(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"httpx", args{"www.sina.com.cn\nhttps://www.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoHttpx(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}

func TestDoNaabu(t *testing.T) {
	util.DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"naabu", args{"www.sina.com.cn\nhttps://ww.baidu.com:443\n"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoNaabu(tt.args.s); got != tt.want {
				t.Errorf("DoNaabu() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
