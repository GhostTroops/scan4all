package main

import (
	"fmt"
	"github.com/hktalent/scan4all/subfinder"
)

func main() {
	var out = make(chan string, 1000)
	var close chan bool
	go subfinder.DoSubfinder([]string{"51pwn.com"}, out, close)

Close:
	for {
		select {
		case <-close:
			break Close
		case ok := <-out:
			fmt.Println(ok)
		}
	}
}
