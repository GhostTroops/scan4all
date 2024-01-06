package common

import (
	"bytes"
	"github.com/antchfx/xmlquery"
	"log"
	"os"
	"strconv"
	"strings"
)

func GetAttr(att []xmlquery.Attr, name string) string {
	for _, x := range att {
		if x.Name.Local == name {
			return x.Value
		}
	}
	return ""
}

/*
解析nmap xml结果
nmap2json a9f7713f6771cc016d664fc6c2d403beba66edfc.xml true|grep -Ev ":(80|443),"|grep -v "secure-mqtt"
筛选出服务名，同时排除 80，443 端口， 排除 secure-mqtt 服务
nmap2json a9f7713f6771cc016d664fc6c2d403beba66edfc.xml true|grep -Ev ":(80|443),"|grep -v "secure-mqtt"|jq ".ports[].service"|sort -u
提取出所有端口，验证是否支持https
nmap2json a9f7713f6771cc016d664fc6c2d403beba66edfc.xml true|grep -Ev ":(80|443),"|grep -v "secure-mqtt"|jq '[.domain[0],.ports[0].port]|@csv'|tr -d '"'|tr -d '\\'|sed 's/,/:/g'|xargs -I % echo "https://%"|httpx -json -o nmapOtherPort.json -title -websocket -method -server -location -ip  -pipeline -csp-probe -http2 -nc -silent  -cname -t 64
cat nmapOtherPort.json|jq '[.status_code,.url,.webserver]|@csv'|sort -u|sed 's/[\\"]//g'
cat nmapOtherPort.json|jq '[.status_code,.url,.webserver]|@csv'|sort -u|grep -Eo "https:\/\/[^:]+"|sed 's/.*\///g'|sort -u|ipgs|sort

cat rawLst.txt|grep -Eo '(https:\/\/[^\/:]+)'|sed 's/.*\///g'|sort -u|ipgs
*/
func ParseNmapXml(cbk4Line func(*map[string]interface{}), args ...string) {
	for _, sIpt := range args {
		if data, err := os.ReadFile(sIpt); nil == err {
			doc, err := xmlquery.Parse(bytes.NewReader(data))
			if err != nil {
				log.Println("DoParseXml： ", err)
				continue
			}
			for _, n := range xmlquery.Find(doc, "//host") {
				var mNode = map[string]interface{}{}
				hostName := n.SelectElements("hostnames/hostname")
				var aDns []string
				for _, x := range hostName {
					aDns = append(aDns, GetAttr(x.Attr, "name"))
				}
				if nil != aDns && 0 < len(aDns) {
					mNode["domain"] = aDns
				}
				x1 := n.SelectElement("address").Attr[0].Value
				mNode["ip"] = x1
				if 0 == len(aDns) {
					aDns = append(aDns, x1)
				}
				ps := n.SelectElements("ports/port")
				var aPot []interface{}
				for _, x := range ps {
					if nil == x {
						continue
					}
					var mPort = map[string]interface{}{}
					oState := x.SelectElement("state")
					if nil == oState || 0 == len(oState.Attr) {
						continue
					}
					if "open" == oState.Attr[0].Value {
						sz1 := GetAttr(x.Attr, "protocol")
						mPort["protocol"] = sz1

						szPort := GetAttr(x.Attr, "portid")
						port, _ := strconv.Atoi(szPort)
						mPort["port"] = port
						if oSvs := x.SelectElement("service"); nil != oSvs {
							service := strings.ToLower(GetAttr(oSvs.Attr, "name"))
							mPort["service"] = service
						}
						aPot = append(aPot, mPort)
						mNode["port"] = mPort
						cbk4Line(&mNode)
						//if data1, err1 := util.Json.Marshal(mNode); nil == err1 {
						//	cbk4Line(string(data1))
						//}
					}
				}
			}
		}
	}
}
