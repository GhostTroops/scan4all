package dnsxx

import (
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pkg/httpx/runner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"gorm.io/gorm"
	"log"
	"net"
	"strings"
)

type Dns2IpMap struct {
	gorm.Model
	Dns string `json:"dns" gorm:"unique_index:dns_ip;type:varchar(100);"`
	Ip  string `json:"ip"  gorm:"unique_index:dns_ip;type:varchar(60);"`
}

// 通过ip查找域名信息
func GetDns2IpMap4Ip(ip string) *[]Dns2IpMap {
	x1 := util.Query4Lists[Dns2IpMap]("ip=?", ip)
	return x1
}

// 获取域名和ip的对照信息
func DoGetDnsInfos(t string) *[]Dns2IpMap {
	if iputil.IsIP(t) {
		return nil
	}
	// , "-json" 输出格式不太友好
	var szW string = util.SzPwd + "/config/databases/subdomain.txt"
	if !strings.HasPrefix(t, "*.") {
		// 历史结果匹配
		x1 := util.Query4Lists[Dns2IpMap]("dns=?", t)
		if nil != x1 && 0 < len(*x1) {
			return x1
		}

		x0 := strings.Split(t, ".")
		szW = x0[0]
		t = strings.Join(x0[1:], ".")
	} else {
		t = t[2:]
	}
	options := ParseOptions("-d", t, "-w", szW, "-resp", "-a", "-aaaa", "-cname", "-mx", "-ns", "-soa", "-txt")
	dnsxRunner, err := New(options)
	if err != nil {
		gologger.Debug().Msgf("Could not create runner: %s\n", err)
		return nil
	}
	util.RegCbk("exit", func() {
		dnsxRunner.Close()
		if options.ShouldSaveResume() {
			gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFile)
			err := dnsxRunner.SaveResumeConfig()
			if err != nil {
				gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}
		}
	})
	// nolint:errcheck
	var a1 []Dns2IpMap
	dnsxRunner.Run(func(s <-chan string) {
		for k := range s {
			// 如何存储才更加好访问
			a1 = append(a1, *ParseLine(k)...)
			log.Println("xx", k)
		}
	})
	// 保存数据
	if nil != a1 && 0 < len(a1) {
		if util.Create[Dns2IpMap](a1...) == int64(len(a1)) {
			log.Println("save is ok")
		}
	}
	dnsxRunner.Close()
	return &a1
}

// 简单的模式，避免递归
func GetSimple(s string) *[]string {
	if ips, err := net.LookupIP(s); nil == err {
		var a []string
		for _, x := range ips {
			if x.IsPrivate() {
				continue
			}
			a = append(a, x.String())
		}
		return &a
	}
	return nil
}

// 这里有可能导致递归、重复
func ParseLine(s string) *[]Dns2IpMap {
	a := strings.Split(s, " [")
	ip1 := a[1][0 : len(a[1])-1]
	if iputil.IsIP(ip1) {
		// 私有ip就不处理了
		if net.ParseIP(ip1).IsPrivate() {
			return &[]Dns2IpMap{}
		}
		return &[]Dns2IpMap{Dns2IpMap{Dns: a[0], Ip: ip1}}
	} else {
		var x1 []Dns2IpMap
		if ips := GetSimple(ip1); nil != ips && 0 < len(*ips) {
			for _, x5 := range *ips {
				x1 = append(x1, Dns2IpMap{Dns: ip1, Ip: x5})
			}
		}
		return &x1
	}
}
