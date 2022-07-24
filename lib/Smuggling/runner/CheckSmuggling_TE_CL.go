package runner

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/Smuggling"
	"github.com/hktalent/scan4all/lib/socket"
	"strings"
)

// check HTTP Request Smuggling
// https://github.com/nodejs/llhttp/blob/master/src/llhttp/http.ts#L483
func Check_TE_CL(target string, port int) bool {
	s1 := socket.NewCheckTarget(target, "tcp", port, 15).SendOnePayload(fmt.Sprintf(Smuggling.TE_Payload[0], fmt.Sprintf("%s:%d", target, port)))
	if "" != s1 {
		a := strings.Split(s1, "HTTP/1.1")
		if 3 <= len(a) {
			return true
		}
	}

	return false
}
