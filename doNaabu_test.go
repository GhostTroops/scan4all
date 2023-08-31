package main

import (
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pkg/xcmd"
	"log"
	"strings"
	"testing"
)

func DoInitAll() {
	util.DoInit(&config)
}

func TestDoUncover(t *testing.T) {
	DoInitAll()
	a := strings.Split(`
'ssl:Alibaba'
'gov.cn'
'ssl:"gov.cn"'
'ssl:"China Lodging Group"'
'ssl:"huazhu"'
'ssl:"huazhu.com"'
'ssl:"alipay.com"'
'ssl:"hackerone.com"'
'ssl:"paypal.com"'
'ssl:"PayPal, Inc."'
'ssl:"tencent"'
'ssl:"paypal"'
'ssl:"paypal.com"'`, "\n")
	for _, x := range a {
		if got := xcmd.DoUncover(x); got != "" {
			log.Println(got)
		}
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoAmass(t *testing.T) {
	DoInitAll()
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
	DoInitAll()
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
	DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"shuffledns", args{"huazhu.com"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoShuffledns(tt.args.s); got != tt.want {
				t.Errorf("DoShuffledns() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoKatana(t *testing.T) {
	DoInitAll()
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
	DoInitAll()
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"tlsx", args{`mercure.huazhu.com
wifi.huazhu.com
checkin.huazhu.com
cdn.huazhu.com
img3.huazhu.com
ota.huazhu.com
sms.huazhu.com
hms.huazhu.com
ehk.huazhu.com
stalker.huazhu.com
msoid.huazhu.com
ssl.huazhu.com
zzyg.huazhu.com
p.huazhu.com
homs.huazhu.com
ir.huazhu.com
d.huazhu.com
fuli.huazhu.com
mail2.huazhu.com
benefit.huazhu.com
excashier.huazhu.com
track.huazhu.com
mms.huazhu.com
seal.huazhu.com
vip.huazhu.com
fr.huazhu.com
srm.huazhu.com
career.huazhu.com
edm.huazhu.com
img2.huazhu.com
campus.huazhu.com
tqm.huazhu.com
gpn.huazhu.com
yiqi.huazhu.com
mx3.huazhu.com
smarthome.huazhu.com
ccapi.huazhu.com
appservice.huazhu.com
cc.huazhu.com
webmail.huazhu.com
mas.huazhu.com
av.huazhu.com
h5.huazhu.com
bm.huazhu.com
mt.huazhu.com
rms.huazhu.com
mbs.huazhu.com
mobile.huazhu.com
wso.huazhu.com
fuli.huazhu.com
track.huazhu.com
mobile.huazhu.com
assist.huazhu.com
booking.huazhu.com
i.huazhu.com
my.huazhu.com
ygg.huazhu.com
gslb.huazhu.com
hxr.huazhu.com
qa.huazhu.com
epos.huazhu.com
research.huazhu.com
web.huazhu.com
hotels.huazhu.com
m.huazhu.com
appapi.huazhu.com
passport.huazhu.com
wxapi.huazhu.com
nexus.huazhu.com
api.huazhu.com
upload.huazhu.com
webcs2.huazhu.com
app6.huazhu.com
app.huazhu.com
promotion.huazhu.com
customer.huazhu.com
hud.huazhu.com
kaifa.huazhu.com
hpd.huazhu.com
hec.huazhu.com
gw.huazhu.com
idp.huazhu.com
breakfast.huazhu.com
vat.huazhu.com
signin.huazhu.com
cashier.huazhu.com
inside.huazhu.com
shop.huazhu.com
hsc.huazhu.com
mx13.huazhu.com
mx15.huazhu.com
mx14.huazhu.com
mx11.huazhu.com
power.huazhu.com
hfs.huazhu.com
services.huazhu.com
hos.huazhu.com`}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xcmd.DoTlsx(tt.args.s); got != tt.want {
				t.Errorf("DoTlsx() = %v, want %v", got, tt.want)
			}
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
func TestDoDnsx(t *testing.T) {
	DoInitAll()
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
	DoInitAll()
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
	DoInitAll()
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
	DoInitAll()
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
