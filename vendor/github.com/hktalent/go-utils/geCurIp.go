package go_utils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/hktalent/htmlquery"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var skpMac = regexp.MustCompile(`docker|lo|utun|gif|stf|awd`)

// 获取当前 mac 地址 hex 格式，可以作为 51pwn.com 的前缀
func GetActiveMac() string {
	ifc, err := net.Interfaces()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	var a []string
	for _, i := range ifc {
		if 0 < len(skpMac.FindAllString(i.Name, -1)) {
			continue
		}
		macAddr := strings.TrimSpace(hex.EncodeToString(i.HardwareAddr))
		// interface down; loopback interface
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || macAddr == "" {
			continue
		}

		addrs, _ := i.Addrs()
		bHb := false
		for _, addr := range addrs {
			if bHb {
				break
			}
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				if !ip.IsPrivate() {
					continue
				}
				a = append(a, macAddr)
				bHb = true
				fmt.Println(macAddr, ip, addr.String(), addr.Network(), i.Flags.String())
				break
			}
		}
	}
	if 0 < len(a) {
		return strings.Join(a, ",")
	} else {
		m1 := GetIp()
		if nil != m1 {
			szIp := fmt.Sprintf("%v", (*m1)["ip"])
			return Pack32BinaryIP4(szIp)
		}
		return ""
	}
}
func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

// Pack32BinaryIP4("127.0.0.1") 7f000001
// Pack32BinaryIP4("192.168.0.1") c0a80001
func Pack32BinaryIP4(ip4Address string) string {
	ipv4Decimal := IP4toInt(net.ParseIP(ip4Address))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint32(ipv4Decimal))

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
	}

	// present in hexadecimal format
	result := fmt.Sprintf("%x", buf.Bytes())
	return result
}

var PubIp *map[string]interface{}

// map[ad_info:map[adcode:510105 city:成都市 district:xxx nation:中国 province:四川省] ip:117.76.248.175 location:map[lat:30.67485 lng:104.06291]]
/**
{
    "ip": "117.176.248.75",
    "network": "117.176.240.0/20",
    "version": "IPv4",
    "city": "Chengdu",
    "region": "Sichuan",
    "region_code": "SC",
    "country": "CN",
    "country_name": "China",
    "country_code": "CN",
    "country_code_iso3": "CHN",
    "country_capital": "Beijing",
    "country_tld": ".cn",
    "continent_code": "AS",
    "in_eu": false,
    "postal": null,
    "latitude": 30.6498,
    "longitude": 104.0555,
    "timezone": "Asia/Shanghai",
    "utc_offset": "+0800",
    "country_calling_code": "+86",
    "currency": "CNY",
    "currency_name": "Yuan Renminbi",
    "languages": "zh-CN,yue,wuu,dta,ug,za",
    "country_area": 9596960.0,
    "country_population": 1411778724,
    "asn": "AS9808",
    "org": "China Mobile Communications Group Co., Ltd."
}
*/
func GetFromIpapi() *map[string]interface{} {
	m1 := map[string]interface{}{}
	szUrl := "https://ipapi.co/json/"
	c := GetClient(szUrl)
	c.DoGetWithClient4SetHd(c.GetClient4Http2(), szUrl, "GET", nil, func(resp *http.Response, err error, szU string) {
		if nil == err && nil != resp {
			if data, err := io.ReadAll(resp.Body); nil == err {
				if nil == Json.Unmarshal(data, &m1) {
					m2 := map[string]interface{}{}
					m1["location"] = m2
					m2["lat"] = m1["latitude"]
					m2["lng"] = m1["longitude"]
					delete(m1, "latitude")
					delete(m1, "longitude")
					m3 := map[string]interface{}{}
					m1["ad_info"] = m3
					m3["city"] = m1["city"]
					m3["country"] = m1["country"]
					delete(m1, "city")
					delete(m1, "country")
				}
			}
		}
	}, func() map[string]string {
		return map[string]string{
			"authority":       "ipapi.co",
			"accept":          "*/*",
			"accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
			"referer":         "https://ipapi.co/",
			"sec-ch-ua":       `"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"`,
			"sec-fetch-site":  "same-origin",
			"user-agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
		}
	}, true)
	return &m1
}

func GetFromIplocation() *map[string]interface{} {
	m1 := map[string]interface{}{}
	if doc, err := htmlquery.LoadURL("https://iplocation.com"); nil == err {
		if node, err := htmlquery.Query(doc, "body > div.top-container > div.bottom-container > div.rubber-container.result > div > table > tbody > tr:nth-child(1) > td > b"); nil == err {
			m1["ip"] = node.Data
		}
		m2 := map[string]interface{}{}
		m1["location"] = m2
		if node, err := htmlquery.Query(doc, "body > div.top-container > div.bottom-container > div.rubber-container.result > div > table > tbody > tr:nth-child(2) > td"); nil == err {
			m2["lat"] = node.Data
		}
		if node, err := htmlquery.Query(doc, "body > div.top-container > div.bottom-container > div.rubber-container.result > div > table > tbody > tr:nth-child(3) > td"); nil == err {
			m2["lng"] = node.Data
		}
		m3 := map[string]interface{}{}
		m1["ad_info"] = m3
		if node, err := htmlquery.Query(doc, "body > div.top-container > div.bottom-container > div.rubber-container.result > div > table > tbody > tr:nth-child(6) > td"); nil == err {
			m3["city"] = node.Data
		}
		if node, err := htmlquery.Query(doc, "body > div.top-container > div.bottom-container > div.rubber-container.result > div > table > tbody > tr:nth-child(4) > td > span"); nil == err {
			m3["country"] = node.Data
		}
	}
	return &m1
}

// 当前ip,自动跳过socks proxy
// X-Limit: current_qps=1; limit_qps=50; current_pv=10197; limit_pv=1000000
func GetIp() *map[string]interface{} {
	szIp := GetPublicIp()
	if nil != Cache1 {
		if oM, err := GetAny[map[string]interface{}](szIp); nil == err && 0 < len(oM) {
			return &oM
		}
	}
	if nil != PubIp && 0 < len(*PubIp) {
		return PubIp
	}
	szUrl := "https://apis.map.qq.com/ws/location/v1/ip"
	c := GetClient(szUrl)
	c.UseHttp2 = false
	var m1 map[string]interface{}
	p11 := c.GetClient(nil)
	c.DoGetWithClient4SetHd(p11, szUrl, "POST", strings.NewReader("key="+url.QueryEscape("IVOBZ-QNW6P-SUKDY-LFQSE-LUFCJ-3CFUE")+"&sig=afebe5ad5227ec75a1f3d8b97f888cda"), func(r *http.Response, err1 error, szU string) {
		if nil == err1 && nil != r {
			defer r.Body.Close()
			if data, err := io.ReadAll(r.Body); nil == err {
				log.Println(string(data))
				if nil == Json.Unmarshal(data, &m1) {
					log.Printf("%+v", m1)
				}
			}
		}
	}, func() map[string]string {
		return map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0", "Accept": "*/*"}
	}, false)
	if m2, ok := m1["result"]; ok {
		m1 = m2.(map[string]interface{})
	} else { // 失败，用其他方法获取
		m1 = *GetFromIpapi()
		bOk := false
		if x1, ok := m1["location"]; ok {
			if x2, ok := x1.(map[string]interface{}); ok {
				if _, ok := x2["lat"]; ok {
					bOk = true
				}
			}
		}
		if !bOk {
			m1 = *GetFromIplocation()
		}
	}
	PubIp = &m1
	PutAny[map[string]interface{}](szIp, m1)
	return PubIp
}
