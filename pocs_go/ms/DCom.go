package ms

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// 135 port
func CheckDCom(host string) ([]string, error) {
	timeout := 3000 * time.Millisecond
	d := net.Dialer{Timeout: timeout}
	tcpcon, err := d.Dial("tcp", host+":135")
	if err != nil {
		return nil, err
	}
	defer tcpcon.Close()
	sendData := "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
	n, err := tcpcon.Write([]byte(sendData))
	if err != nil {
		return nil, err
	}
	recvData := make([]byte, 4096)
	readTimeout := 3 * time.Second
	err = tcpcon.SetReadDeadline(time.Now().Add(readTimeout))
	n, err = tcpcon.Read(recvData)
	if err != nil {
		return nil, err
	}
	sendData2 := "\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
	n, err = tcpcon.Write([]byte(sendData2))
	if err != nil {
		return nil, err
	}
	err = tcpcon.SetReadDeadline(time.Now().Add(readTimeout))
	n, err = tcpcon.Read(recvData)
	if err != nil {
		return nil, err
	}
	recvStr := string(recvData[:n])
	if len(recvStr) > 42 {
		recvStr_v2 := recvStr[42:]
		packet_v2_end := strings.Index(recvStr_v2, "\x09\x00\xff\xff\x00\x00")
		if -1 == packet_v2_end {
			return nil, nil
		}
		packet_v2 := recvStr_v2[:packet_v2_end]
		hostname_list := strings.Split(packet_v2, "\x00\x00")
		if len(hostname_list) > 1 {
			for _, value := range hostname_list {
				if strings.Trim(value, " ") != "" {
					fmt.Println(strings.Replace(value, string([]byte{0x00}), "", -1))
				}
			}
			return hostname_list, nil
		}
	}
	return nil, nil

}
