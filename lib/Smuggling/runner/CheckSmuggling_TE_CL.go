package runner

import (
	pas "github.com/hktalent/scan4all/lib/Smuggling"
	"github.com/hktalent/scan4all/lib/socket"
	"github.com/hktalent/scan4all/lib/util"
	"net/url"
	"strconv"
	"strings"
)

type Smuggling interface {
	Check(rc *CheckTarget)
}

var payload = []Smuggling{&pas.ClTe{}, &pas.TeCl{}, &pas.TeTe{}}

func CheckSmuggling(szUlr string) {
	u, err := url.Parse(szUlr)
	if err == nil {
		port := 80
		if strings.ToLower(u.Scheme) == "https" {
			port = 443
		}
		if "" != u.Port() {
			n, err := strconv.Atoi(u.Port())
			if nil == err {
				port = n
			}
		}
		for _, x := range payload {
			util.Wg.Add(1)
			go func(j Smuggling) {
				defer util.Wg.Done()
				x1 := socket.NewCheckTarget(u.Hostname(), "tcp", port, 15)
				defer x1.Close()
			}(x)
		}
	}
}

// check HTTP Request Smuggling
// https://hackerone.com/reports/1630668
// https://github.com/nodejs/llhttp/blob/master/src/llhttp/http.ts#L483
//func Check_TE_CL(target string, port int) bool {
//	s1 := socket.NewCheckTarget(target, "tcp", port, 15).SendOnePayload(fmt.Sprintf(Smuggling.TeClPayload[0], fmt.Sprintf("%s:%d", target, port)))
//	if "" != s1 {
//		a := strings.Split(s1, "HTTP/1.1")
//		if 3 <= len(a) {
//			return true
//		}
//	}
//
//	return false
//}
