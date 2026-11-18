package giop

import (
	"encoding/hex"
	"fmt"
	"net"
)

func GetVersion(host, vp string, port int) string {
	conn, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return ""
	}
	payload, err := hex.DecodeString(vp)
	if err != nil {
		return ""
	}
	_, err = conn.Write(payload)
	if err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)
	ver := buf[5:7]
	if ver[0] == 0x00 || ver[1] == 0x00 {
		return ""
	}
	return string(ver)
}
