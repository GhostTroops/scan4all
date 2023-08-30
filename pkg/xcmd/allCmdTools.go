package xcmd

import (
	"bufio"
	"fmt"
	"github.com/hktalent/ProScan4all/lib/util"
	Const "github.com/hktalent/go-utils"
	"log"
	"os"
	"strings"
)

type CmdCbk func(string) string

/*
年：31536000000 毫秒
月：2592000000毫秒
天：86400000
小时：3600000毫秒
go install github.com/OJ/gobuster/v3@latest
*/
func init() {
	util.RegInitFunc(func() {
		for k, v := range map[uint64]CmdCbk{
			Const.ScanType_Naabu:      DoNaabu,
			Const.ScanType_Httpx:      DoHttpx,
			Const.ScanType_Nuclei:     DoNuclei,
			Const.ScanType_DNSx:       DoDnsx,
			Const.ScanType_Tlsx:       DoTlsx,
			Const.ScanType_Katana:     DoKatana,
			Const.ScanType_Shuffledns: DoShuffledns,
			Const.ScanType_Subfinder:  DoSubfinder,
			Const.ScanType_Amass:      DoAmass,
			Const.ScanType_Ffuf:       DoFfuf,
			Const.ScanType_Uncover:    DoUncover,
			Const.ScanType_Gobuster:   DoGobuster,
		} {
			//v = ParseOut(k, v)
			func(nT uint64, cbk CmdCbk) {
				util.EngineFuncFactory(k, func(evt *Const.EventData, args ...interface{}) {
					s := strings.Join(util.CvtData(evt.EventData), "\n")
					ParseOut(nT, evt.EventType, cbk)(s)
				})
			}(k, v)
		}
	})
}

// 逐行扫描结果，并返回 chan
func ParseOutJson4Line(s string) <-chan *map[string]interface{} {
	buf := bufio.NewScanner(strings.NewReader(s))
	var out = make(chan *map[string]interface{})
	util.DoSyncFunc(func() {
		defer close(out)
		for buf.Scan() {
			var m = map[string]interface{}{}
			s1 := strings.TrimSpace(buf.Text())
			if 6 >= len(s1) { // {"1":1}
				continue
			}
			if err := util.Json.Unmarshal([]byte(s1), &m); nil == err {
				out <- &m
			} else {
				log.Println("ParseOutJson4Line -> json.Unmarshal", err, s1)
			}
		}
	})
	return out
}

// 基于回调函数，处理行
func DoOutJson4Lines(s string, cbk func(*map[string]interface{})) {
	out := ParseOutJson4Line(s)
	for x := range out {
		cbk(x)
	}
}

func CvtItfc(m *map[string]interface{}, a ...string) []interface{} {
	var aR []interface{}
	m1 := *m
	for _, x := range a {
		if o, ok := m1[x]; ok {
			switch o.(type) {
			case string:
				aR = append(aR, o)
			case interface{}:
				if oA, ok := o.([]interface{}); ok {
					aR = append(aR, oA...)
				} else {
					aR = append(aR, o)
				}
			}
		}
	}
	return aR
}

// 解析结果的包装，便于将结果传递到下一层流程
func ParseOut(nType, rawType uint64, fnCbk CmdCbk) CmdCbk {
	return func(s string) string {
		s1 := fnCbk(s)
		xEt := ^nType & rawType
		switch nType {
		// {"host":"www.baidu.com","ip":"104.193.88.123","port":443,"timestamp":"2023-01-08T14:58:44.115411Z"}
		case Const.ScanType_Naabu:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {
				m1 := *m
				util.SendEvent(&Const.EventData{
					EventType: xEt,
					EventData: []interface{}{fmt.Sprintf("%v:%d", m1["host"], m1["port"]), fmt.Sprintf("%v:%d", m1["ip"], m1["port"])},
				})
			})
		// {"timestamp":"2023-01-08T23:18:44.757246+08:00","hash":{"body_md5":"5cf3b0c5e0285fbad7e312e5ed95fd4b","body_mmh3":"-983595835","body_sha256":"7f335bced6015416c675987323e16468a95d259bf0fc9f8af316d10cb56c1d4d","body_simhash":"9827907017474422702","header_md5":"2300e055a48aec993e56a9b1e335a927","header_mmh3":"-972303241","header_sha256":"0b2cf3d67a00796be4c20cdd97eb20d62496bfb1bef6c7fc247df7af69b0b556","header_simhash":"11021017588798556011"},"port":"443","url":"https://www.baidu.com:443","input":"www.baidu.com","title":"百度一下","scheme":"https","webserver":"apache","content_type":"text/html","method":"GET","host":"39.156.66.18","path":"/","time":"2.320031121s","a":["39.156.66.18","39.156.66.14"],"cname":["www.a.shifen.com"],"tech":["Apache","HSTS"],"words":3937,"lines":3,"status_code":200,"content_length":205250,"failed":false}
		case Const.ScanType_Httpx:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {
				eD1 := CvtItfc(m, "url", "a", "cname")
				util.SendEvent(&Const.EventData{
					EventType: xEt,
					EventData: eD1,
				})
				// 假定，所有命令结果都保存到库，其他命令从库中获取附加参数，例如 tech，所以，这里不再单独派发辅助参数
			})
		case Const.ScanType_Nuclei:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {

			})
		case Const.ScanType_DNSx:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {

			})
		case Const.ScanType_Tlsx:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {

			})
		case Const.ScanType_Katana:
		case Const.ScanType_Shuffledns:
		case Const.ScanType_Subfinder:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {

			})
		case Const.ScanType_Amass:
		case Const.ScanType_Ffuf:
		case Const.ScanType_Uncover:
			DoOutJson4Lines(s1, func(m *map[string]interface{}) {

			})
		case Const.ScanType_Gobuster:
		}
		// 解析结果
		log.Println(s1)

		return s1
	}
}

/*
gobuster dns -d qq.com -c -w config/database/subdomain.txt
gobuster dir -t 64 -u https://127.0.0.1:8081/ -H 'Cookie: JSESSIONID=353170776e;rememberMe=123' --no-status -k --random-agent -w $HOME/MyWork/scan4all/brute/dicts/filedic.txt -o xxx.txt
*/
func DoGobuster(s string) string {
	szName, _ := GetTempFile() // 输出的文件名
	s1 := doTpCmdN("gobuster", s, szName, 2)

	return s1
}

func DoKsubdomain(s string) string {
	szName, _ := GetTempFile() // 输出的文件名
	os.WriteFile(szName, []byte(s), os.ModePerm)
	t := "ksubdomain"
	a := GetCmdParms(t)
	a[10] = szName
	szRst := DoAsyncCmd(t, a...)
	//if util.FileExists(o) {
	//	os.Remove(o)
	//}
	return szRst
}

// 传入目标数据，转换为临时文件名
//
//	最后一次参数为输出文件名
//	内、外网都做
//
// full,100,1000,
func DoNaabu(s string) string {
	return DoTargetHost(s, "naabu")
}

// 传入目标数据，转换为临时文件名
//  最后一次参数为输出文件名
/*
   -rl, -rate-limit int          maximum requests to send per second (default 150)
   -rlm, -rate-limit-minute int  maximum number of requests to send per minute
	-probe-all-ips        probe all the ips associated with same host
 	-path string               path or list of paths to probe (comma-separated, file)
	-H, -header string[]          custom http headers to send with request
	-fr, -follow-redirects        follow http redirects
	-follow-host-redirects  follow redirects on the same host

"-ports","http:1-65535,https:1-65535",

{"timestamp":"2022-11-16T18:22:46.358561+08:00","asn":{"as_number":"AS3356","as_name":"LEVEL3","as_country":"US","as_range":["8.11.2.0/23","8.11.4.0/22","8.11.8.0/21","8.11.16.0/20","8.11.32.0/19","8.11.64.0/18","8.11.128.0/17","8.12.0.0/14","8.16.0.0/12","8.32.0.0/11","8.64.0.0/10"]},"hash":{"body_sha1":"ec389ccce387d7c7360618020ecbd8ce502739de","header_sha1":"8d2bf5e7eaa5d4ac62d4a8be3660a8b537035209"},"port":"80","url":"http://www.sina.com.cn:80","input":"www.sina.com.cn","location":"https://www.sina.com.cn/","title":"302 Found","scheme":"http","webserver":"Tengine","content_type":"text/html","method":"GET","host":"8.45.176.231","path":"/","favicon":"-1840324437","time":"447.372648ms","a":["8.45.176.225","8.45.176.227","8.45.176.232","8.45.176.228","8.45.176.229","8.45.176.231","8.45.176.226"],"cname":["spool.grid.sinaedge.com","ww1.sinaimg.cn.w.alikunlun.com"],"tech":["Tengine"],"words":18,"lines":9,"status_code":302,"content_length":242,"failed":false,"vhost":true,"pipeline":true}
{"timestamp":"2022-11-16T18:22:46.461904+08:00","asn":{"as_number":"AS3356","as_name":"LEVEL3","as_country":"US","as_range":["8.11.2.0/23","8.11.4.0/22","8.11.8.0/21","8.11.16.0/20","8.11.32.0/19","8.11.64.0/18","8.11.128.0/17","8.12.0.0/14","8.16.0.0/12","8.32.0.0/11","8.64.0.0/10"]},"hash":{"body_sha1":"ec389ccce387d7c7360618020ecbd8ce502739de","header_sha1":"9b24d16abaaf483e259440356daae71e3cf66efc"},"port":"80","url":"http://www.sina.com.cn:80","input":"www.sina.com.cn","location":"https://www.sina.com.cn/","title":"302 Found","scheme":"http","webserver":"Tengine","content_type":"text/html","method":"GET","host":"8.45.176.229","path":"/","favicon":"-1840324437","time":"473.5599ms","a":["8.45.176.225","8.45.176.227","8.45.176.232","8.45.176.228","8.45.176.229","8.45.176.231","8.45.176.226"],"cname":["spool.grid.sinaedge.com","ww1.sinaimg.cn.w.alikunlun.com"],"tech":["Tengine"],"words":18,"lines":9,"status_code":302,"content_length":242,"failed":false,"vhost":true,"pipeline":true}

cat sample/httpx.json|jq ".tech"
 内、外网都做
*/
func DoHttpx(s string) string {
	return DoRawCmd(s, "httpx")
}

// 原样输入执行命令 t， s 为输入， szName 输出
func DoRawCmd(s, t string) string {
	s = TargetRaw2HostsFile(s)
	szName, _ := GetTempFile()
	return doTpCmd(t, s, szName)
}

/*
-automatic-scan                   automatic web scan using wappalyzer technology detection to tags mapping
-no-strict-syntax                Disable strict syntax check on templates
-report-db string       nuclei reporting database (always use this to persist report data)
-ztls                          use ztls library with autofallback to standard one for tls13
Out-of-band application security testing (OAST)

	  -cloud                      run scan on nuclei cloud
	  -cs, -cloud-server string   nuclei cloud server to use (default "http://cloud-dev.nuclei.sh")
	  -ak, -cloud-api-key string  api-key for the nuclei cloud server

	./tools/macOS/nuclei -l  tools/xx.txt -t $PWD/config/nuclei-templates,$PWD/config/51pwn -nss -severity critical,high,medium -type http,network,websocket,dns -report-config ./config/nuclei_esConfig.yaml -ztls -config-directory ./config/nuclei -max-host-error 5 -duc -nc -json -o xxx1.json
	内、外网都做

+tools:"nuclei" +ip:"202.51.189.217"
*/
func DoNuclei(s string) string {
	return DoRawCmd(s, "nuclei")
}

// 执行命令t，转换目标不包含 http[s]://
//
//	s 为 输入
func DoTargetHost(s, t string) string {
	s = Target2HostsFile(s)
	szName, _ := GetTempFile()
	return doTpCmd(t, s, szName)
}

// 执行dnsx， 只做外网目标
func DoDnsx(s string) string {
	return DoTargetHost(s, "dnsx")
}

// tlsx -u www.sina.com.cn -p 443 -scan-mode auto -san -ps -scan-all-ips -ip-version 4,6   -c 300
// tools/macOS/tlsx -l xxx -p 443 -scan-mode auto -ps -scan-all-ips -ip-version 4,6 -so -tls-version -cipher -hash sha1 -jarm -ja3 -wildcard-cert -probe-status -expired -self-signed -mismatched -revoked -c 300 -silent -nc -json -o xxx
// -version-enum
// -cipher-enum
//
//	       "-san",
//	只做 https
//
// tlsx -u www.sina.com.cn -json -silent | jq .
// cmd:"tlsx"
func DoTlsx(s string) string {
	return DoTargetHost(s, tlsx)
}

// -no-scope                   disables host based default scope
//
//	爬虫
func DoKatana(s string) string {
	return DoRawCmd(s, "katana")
}

// 这个没有太大用
// 子域名枚举
func DoShuffledns(s string) string {
	s = strings.Join(strings.Split(strings.TrimSpace(s), "\n"), ",")
	szName, _ := GetTempFile()
	return doTpCmd(shuffledns, s, szName)
}

// 这个没有太大用
func DoSubfinder(s string) string {
	return DoTarget4SubDomain(s, "subfinder")
}

func DoTarget4SubDomain(s, t string) string {
	s = Target4SubDomainNoFile(s)
	szName, _ := GetTempFile()
	return doTpCmdN(t, s, szName, 2)
}

// https://github.com/OWASP/Amass/blob/master/doc/user_guide.md
func DoAmass(s string) string {
	return DoTarget4SubDomain(s, "amass")
}

/*
	https://github.com/ffuf/ffuf
	-recursion          Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
	-recursion-depth    Maximum recursion depth. (default: 0)

-d                  POST data

	ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
ffuf -w /path/to/postdata.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401
*/
func DoFfuf(s string) string {
	return DoRaw4FuzzCmd(s, "ffuf")
}

func DoRaw4FuzzCmd(s, t string) string {
	s = Target2Hosts4Fuzz(s, "/FUZZ")
	szName, _ := GetTempFile()
	return doTpCmd(t, s, szName)
}

/*
ssl:".edu" country:"US"

	./uncover -q 'ssl:"paypal.com"'  -e shodan -pc ../../config/uncover/provider-config.yaml  -config ../../config/uncover/config.yaml -f ip,port,host -json -o paypal1.json

./uncover -q 'ssl:".gov" country:"US"' -l 500000  -e shodan -pc ../../config/uncover/provider-config.yaml  -config ../../config/uncover/config.yaml -f ip,port,host -json -o edu.json

'ssl:"China Lodging Group"'
'ssl:"huazhu"'
'ssl:"huazhu.com"'
'ssl:"alipay.com"'
'ssl:"hackerone.com"'
'ssl:"paypal.com"'
'ssl:"PayPal, Inc."'
'ssl:"tencent"'
'ssl:"paypal"'
'ssl:"paypal.com"'
*/
func DoUncover(s string) string {
	t := uncover
	a := GetCmdParms(t)
	a = DoParms(a...)
	a[1] = s
	szName, _ := GetTempFile()
	a[len(a)-1] = szName
	szRst := DoAsyncCmd(t, a...)
	if util.FileExists(szName) {
		os.Remove(szName)
	}
	return szRst
}
