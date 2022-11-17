package xcmd

// 传入目标数据，转换为临时文件名
//  最后一次参数为输出文件名
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
*/
func DoHttpx(s string) string {
	return DoRawCmd(s, "httpx")
}

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
*/
func DoNuclei(s string) string {
	return DoRawCmd(s, "nuclei")
}

func DoTargetHost(s, t string) string {
	s = Target2HostsFile(s)
	szName, _ := GetTempFile()
	return doTpCmd(t, s, szName)
}

func DoDnsx(s string) string {
	return DoTargetHost(s, "dnsx")
}

// -version-enum
// -cipher-enum
//         "-san",
func DoTlsx(s string) string {
	return DoTargetHost(s, "tlsx")
}

// -no-scope                   disables host based default scope
func DoKatana(s string) string {
	return DoRawCmd(s, "katana")
}

// 这个没有太大用
func DoShuffledns(s string) string {
	return DoTargetHost(s, "shuffledns")
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
