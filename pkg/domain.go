package pkg

import (
	"crypto/tls"
	"fmt"
	"github.com/hktalent/scan4all/subfinder"
	"reflect"
	"strings"
)

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
	if "*." == s[:2] {
		EnableSubfinder := GetVal("EnableSubfinder")
		if "" != EnableSubfinder {
			var out = make(chan string, 1000)
			var close chan bool
			go subfinder.DoSubfinder([]string{s[2:]}, out, close)
		Close:
			for {
				select {
				case <-close:
					break Close
				case ok := <-out:
					if "" != ok {
						aRst = append(aRst, ok)
						fmt.Println("out ===> ", ok)
					}
				}
			}
		} else {
			aRst = append(aRst, s[2:])
		}
	}
	return aRst, nil
}

// 获取DNS 的所有子域名信息，start from here
func DoDns(s string) (aRst []string, err1 error) {
	if -1 < strings.Index(s, "://") {
		s = strings.Split(s, "://")[1]
	}
	if -1 < strings.Index(s, ":") {
		s = strings.Split(s, ":")[0]
	}

	a1, err := GetSSLDNS(s)
	if nil != err {
		aRst = append(aRst, s)
	} else {
		aRst = append(aRst, a1...)
	}

	var aRst1 = []string{}
	for _, x := range aRst {
		a, err := GetSSLDNS(x)
		if nil == err && 0 < len(a) {
			fmt.Println("GetSSLDNS ", x, " ", a)
			aRst1 = doAppends(aRst1, a)
		}
	}
	if 0 == len(aRst1) {
		aRst1 = aRst
	}
	for _, x := range aRst1 {
		if -1 < strings.Index(x, "*.") {
			a1, err := doSub(x)
			if nil == err && 0 < len(a1) {
				aRst1 = doAppends(aRst1, a1)
			} else {
				aRst1 = doAppends(aRst1, []string{x[2:]})
			}
		}
	}
	aRst = []string{}
	for j, x := range aRst1 {
		if -1 < strings.Index(x, "*.") {
			aRst1[j] = x[2:]
		}
	}
	aRst = doAppends(aRst, aRst1)
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
		//fmt.Print(cert.Issuer)
		//fmt.Print("\nSubject: ")
		//fmt.Print(cert.Subject)
		//fmt.Print("\nSerial Number: ")
		//fmt.Print(cert.SerialNumber)
		//fmt.Print("\nVersion: ")
		//fmt.Print(cert.Version)
		//fmt.Print("\nNot Before: ")
		//fmt.Print(cert.NotBefore)
		//fmt.Print("\nNot After: ")
		//fmt.Print(cert.NotAfter)
		//fmt.Print("\nEmail Addresses: ")
		//fmt.Print(cert.EmailAddresses)
		//fmt.Print("\nIP Addresses: ")
		//fmt.Print(cert.IPAddresses)
		//fmt.Print("\nPermitted DNS Domains: ")
		//fmt.Print(cert.PermittedDNSDomains)
		//fmt.Print("\nExcluded DNS Domains: ")
		//fmt.Print(cert.ExcludedDNSDomains)
		//fmt.Print("\nPermitted IP Ranges: ")
		//fmt.Print(cert.PermittedIPRanges)
		//fmt.Print("\nEXcluded IP Ranges: ")
		//fmt.Print(cert.ExcludedIPRanges)
		//fmt.Print("\nPermitted Email Addresses: ")
		//fmt.Print(cert.PermittedEmailAddresses)
		//fmt.Print("\nExcluded Email Addresses: ")
		//fmt.Print(cert.ExcludedEmailAddresses)
		//fmt.Print("\nPermitted URI Domains: ")
		//fmt.Print(cert.PermittedURIDomains)
		//fmt.Print("\nExlucded URI Domains: ")
		//fmt.Print(cert.ExcludedURIDomains)
		//fmt.Print("\nOCSP Server: ")
		//fmt.Print(cert.OCSPServer)
		//fmt.Print("\nIssuing Certificate URL Server: ")
		//fmt.Print(cert.IssuingCertificateURL)
		//fmt.Print("\nDNS Names: ")
		//fmt.Println(cert.DNSNames)
	}
	return aRst, nil
}
