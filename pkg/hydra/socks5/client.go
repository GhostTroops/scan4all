package socks5

import (
	"fmt"
	sks5 "github.com/txthinking/socks5"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	server := fmt.Sprintf("%s:%d", Host, Port)
	c, _ := sks5.NewClient(server, Username, Password, 5, 5)
	conn, err := c.Dial("tcp", server)
	if nil == err && nil != conn {
		conn.Close()
		return true, nil
	}
	return false, err
}
