package go_utils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/pion/stun"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
)

var szCurIp string

func GBKToUTF8(s []byte) []byte {
	utf8Str := simplifiedchinese.GBK.NewDecoder().Reader(bytes.NewReader(s))
	if data, err := io.ReadAll(utf8Str); nil == err {
		return data
	}
	return nil
}

// 通过cloudflare 获取自己当前互联网 ip
func GetCurPubIp() string {
	szRst := ""
	szUrl := "https://www.cloudflare.com/cdn-cgi/trace"
	DoUrlCbk(szUrl, "", nil, func(resp *http.Response, szUrl string) {
		if data, err := io.ReadAll(resp.Body); nil == err {
			s := string(data)
			if a := strings.Split(s, "ip="); 2 == len(a) {
				a = strings.Split(a[1], "\n")
				if 1 < len(a) {
					szRst = a[0]
				}
			}
		}
	})
	return szRst
}

func DoUrlCbk4byte4Redirect(szUrl string, data []byte, hd map[string]string, cbk func(resp *http.Response, szUrl string), Redirect bool) string {
	szR := ""

	szM := "GET"
	if 0 < len(data) {
		szM = "POST"
	}
	PipE.ErrCount = 0
	PipE.ErrLimit = 999999999
	if Redirect {
		PipE.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return nil
		}
	}
	PipE.DoGetWithClient4SetHd(PipE.Client, szUrl, szM, bytes.NewReader(data), func(resp *http.Response, err error, szU string) {
		if nil == err && nil != resp {
			defer resp.Body.Close()
			cbk(resp, szU)
		} else {
			//log.Println(err)
		}
	}, func() map[string]string {
		return hd
	}, true)
	return szR
}

func DoUrlCbk4byte(szUrl string, data []byte, hd map[string]string, cbk func(resp *http.Response, szUrl string)) string {
	return DoUrlCbk4byte4Redirect(szUrl, data, hd, cbk, false)
}

// 通用的获取数据的方法
func DoUrlCbk(szUrl string, data string, hd map[string]string, cbk func(resp *http.Response, szUrl string)) string {
	return DoUrlCbk4byte(szUrl, []byte(data), hd, cbk)
}

// get ip location
func GetIpLocation(x string) string {
	if m1 := GetIpInfo(x); nil != m1 {
		if a, ok := (*m1)["data"].([]interface{}); ok {
			if 0 < len(a) {
				s := GetJson4Query(a[0], "location")
				return fmt.Sprintf("%v", s)
			}
		}
	}
	return ""
}

var ht1 = PipE.GetClient(nil)

func GetIpInfo2(ip string) *map[string]interface{} {
	var err error
	var ipInfo = map[string]interface{}{}
	PipE.DoGetWithClient4SetHd(ht1, "http://ip-api.com/json/"+ip, "GET", nil, func(resp *http.Response, err1 error, szU string) {
		err = err1
		if resp != nil {
			defer resp.Body.Close() // resp 可能为 nil，不能读取 Body
		}
		if err != nil {
			//log.Println(err)
			return
		}
		err = Json.NewDecoder(resp.Body).Decode(&ipInfo)
	}, func() map[string]string {
		return map[string]string{
			"User-Agent":    "curl/1.0",
			"Cache-Control": "no-cache",
			"Connection":    "close",
		}
	}, true)

	if nil == err {
		return &ipInfo
	}

	return nil
}
func GetIpInfo(s string) *map[string]interface{} {
	m1 := func() *map[string]interface{} {
		var m = &map[string]interface{}{}
		DoUrlCbk("https://opendata.baidu.com/api.php?query="+s+"&resource_id=6006&format=json", "", map[string]string{
			"Cookie":          "BAIDUID=AD297683AEA2BE6DF0794437E0AE9E08:FG=1",
			"User-Agent":      "VideoGo/1897687 CFNetwork/1410.0.3 Darwin/22.6.0",
			"Accept-Language": "zh-CN,zh-Hans;q=0.9",
			"Connection":      "close",
		}, func(resp *http.Response, szUrl string) {
			if data, err := io.ReadAll(resp.Body); nil == err {
				if data1 := GBKToUTF8(data); 0 < len(data1) {
					Json.Unmarshal(data1, m)
				}
			}
		})
		return m
	}()
	if nil == m1 || 0 == len(*m1) {
		if m1 = GetIpInfo2(s); nil != m1 {
			(*m1)["data"] = &map[string]interface{}{"location": fmt.Sprintf("%v %v", (*m1)["country"], (*m1)["city"])}
		}
	}
	return m1
}

//func GetIpaInfo(a []string) {
//	for _, x := range a {
//		if m1 := GetIpInfo(x); nil != m1 {
//			a := (*m1)["data"].([]interface{})
//			if 0 == len(a) {
//				continue
//			}
//			s := GetJson4Query(a[0], "location")
//			if "" == s {
//				continue
//			}
//			fmt.Printf("%s\t%v\n", x, s)
//		}
//	}
//}

// get your public ip
// auto skip proxy
func GetPublicIp() string {
	if "" != szCurIp {
		return szCurIp
	}
	c, err := stun.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		log.Println(err)
		return ""
	}
	szR := ""
	// Building binding request with random transaction id.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	// Sending request to STUN server, waiting for response message.
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			log.Println(err)
			return
		}
		// Decoding XOR-MAPPED-ADDRESS attribute from message.
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			log.Println(err)
		}
		szR = xorAddr.IP.String()
		szCurIp = szR
		fmt.Println("your IP is", szR)
	}); err != nil {
		log.Println(err)
	}
	return szR
}

// Get the Internet egress ip of the current machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// 获取domain的所有ip
func GetIps(domain string) []string {
	UseCacheIp := GetValAsBool("UseCacheIp")
	if UseCacheIp {
		a, err := GetAny[[]string](domain)
		if nil == err {
			return a
		}
	}
	a1 := GetDomian2IpsAll(domain)
	if nil != a1 && 0 < len(a1) {
		go PutAny[[]string](domain, a1)
	}
	return a1
}

// domain
// opType 0 all type，1 ipv4，2 ipv6
func GetDomian2Ips(domain string, opType int) []string {
	ips, _ := net.LookupIP(domain)
	var aIps []string
	for _, ip := range ips {
		if 0 == opType || 1 == opType {
			if ipv4 := ip.To4(); ipv4 != nil {
				aIps = append(aIps, ipv4.String())
			}
		}
		if 0 == opType || 2 == opType {
			if ipv6 := ip.To16(); ipv6 != nil {
				aIps = append(aIps, ipv6.String())
			}
		}
	}
	return aIps
}

func GetDomian2IpsAll(domain string) []string {
	return GetDomian2Ips(domain, 0)
}

// ipv4 to bigint
// ipv6 to bigint
func Ip2Int(ip net.IP) *big.Int {
	i := big.NewInt(0)
	i.SetBytes(ip)
	return i
}

// ipv4 string to bigint
// ipv6 string to bigint
func StrIp2Int(ip string) *big.Int {
	return Ip2Int(net.ParseIP(ip))
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(str string) bool {
	return strings.Count(str, ":") >= 2
}

// big int to Ip
func IntToIpv6(intipv6 *big.Int) *net.IP {
	ip := intipv6.Bytes()
	var a net.IP = ip
	if IsIPv4(a.String()) {
		a = ip[len(ip)-4:]
	}

	ip1 := a.To4()
	if nil != ip1 {
		return &ip1
	}
	return &a
}

// string big int to big int
// If the string input tosetString() starts with “0x” base 16 (hexadecimal) will be used.
//
//	If the string starts with “0” base 8 (octal) will be used.
//
// Otherwise it will use base 10 (decimal)
func Str2BigInt(s string, base int) *big.Int {
	bi := new(big.Int)
	bi.SetString(s, base)
	return bi
}

func FullIPv6(ip net.IP) string {
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}

// big int to ip(v6) string
func IntToIpv6Str(intipv6 *big.Int) string {
	ip := IntToIpv6(intipv6)
	s1 := ip.String()
	if IsIPv4(s1) {
		return s1
	} else {
		return FullIPv6(*ip)
	}
}

// big int to hex, base is 16
func BigInt2Hex(v *big.Int, base int) string {
	return v.Text(base)
}

// int to hex string
func Any2Hex(v interface{}) string {
	data, err := Json.Marshal(v)
	if nil != err {
		log.Println("Any2Hex is error: ", err)
		return ""
	}
	return fmt.Sprintf("%x", data)
}
