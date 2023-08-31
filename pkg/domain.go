package pkg

import (
	"crypto/tls"
	"fmt"
	Const "github.com/hktalent/go-utils"
	"github.com/hktalent/scan4all/lib/util"
	jsoniter "github.com/json-iterator/go"
	"reflect"
	"strings"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// 判断s是否在数组a中
// 支持任何类型，支持泛型
func Contains[T any](a []T, s T) bool {
	for _, x := range a {
		if reflect.DeepEqual(s, x) {
			return true
		}
	}
	return false
}
func Contains4sub[T any](a []T, s T) bool {
	s2 := fmt.Sprintf("%v", s)
	for _, x := range a {
		s1 := fmt.Sprintf("%v", x)
		if -1 < strings.Index(s2, s1) {
			return true
		}
	}
	return false
}

func doAppend(a []string, s string) []string {
	if !Contains[string](a, s) {
		a = append(a, s)
		return a
	}
	return a
}
func doAppends(a []string, s []string) []string {
	for _, x := range s {
		a = doAppend(a, x)
	}
	return a
}

func doSub(s string) (aRst []string, err1 error) {
	if !util.GetValAsBool(util.EnableSubfinder) {
		return
	}
	bSend := false
	if "*." == s[:2] {
		var out = make(chan string, 1000)
		var close chan bool
		util.SendEvent(&Const.EventData{
			EventType: Const.ScanType_Subfinder,
			EventData: []interface{}{s[2:]},
		}, Const.ScanType_Subfinder)
		//go subfinder.DoSubfinder([]string{s[2:]}, out, close)
	Close:
		for {
			select {
			case <-util.Ctx_global.Done():
				return
			case <-close:
				break Close
			case ok := <-out:
				if "" != ok {
					aRst = append(aRst, ok)
					//fmt.Println("out ===> ", ok)
				}
			default:
				util.DoSleep()
			}
		}
		bSend = true
	} else {
		aRst = append(aRst, s[2:])
	}

	if bSend {
		util.SendAData[string](s[:2], aRst, Const.GetTypeName(Const.ScanType_Subfinder))
	}
	return aRst, nil
}

// 获取DNS 的所有子域名信息，start from here
func DoDns(s string) (aRst []string, err1 error) {
	if -1 < strings.Index(s, "://") {
		s = strings.Split(s, "://")[1]
	}
	if -1 < strings.Index(s, "/") {
		s = strings.Split(s, "/")[0]
	}
	if -1 < strings.Index(s, ":") {
		s = strings.Split(s, ":")[0]
	}

	// read from cache
	data, err := util.Cache1.Get(s)
	if nil == err && 0 < len(data) {
		json.Unmarshal(data, &aRst)
		return
	}

	a1, err := GetSSLDNS(s)
	if nil != err {
		aRst = append(aRst, s)
	} else {
		aRst = append(aRst, a1...)
	}
	for _, x := range aRst {
		if -1 < strings.Index(x, "*.") {
			a1, err := doSub(x)
			if nil == err && 0 < len(a1) {
				aRst = doAppends(aRst, a1)
			} else {
				aRst = doAppends(aRst, []string{x[2:]})
			}
		}
	}
	util.PutAny[[]string](s, aRst)
	return aRst, nil
}

// get ssl info DNS
func GetSSLDNS(s string) (aRst []string, err1 error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	host := s + ":443"
	if -1 < strings.Index(s, ":") {
		host = s
	}
	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		err1 = err
		return aRst, err1
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		for _, x := range cert.DNSNames {
			aRst = append(aRst, x)
		}
	}
	return aRst, nil
}
