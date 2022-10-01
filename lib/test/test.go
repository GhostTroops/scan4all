package main

import (
	"github.com/hktalent/scan4all/lib/socket"
	"io/ioutil"
)

func main() {

	data, err := ioutil.ReadFile("/Users/51pwn/MyWork/TestPoc/JRMPListener.ser")
	if nil == err {
		x1 := socket.NewCheckTarget("http://127.0.0.1:4444", "tcp", 15)
		x1.SendPayload(data, 15)
		x1.Close()
	}
}
