package main

import (
	"fmt"
	"github.com/hktalent/scan4all/subfinder"
)

func main() {
	var out = make(chan string, 1000)
	go subfinder.DoSubfinder([]string{"qq.com"}, out)
	for {
		select {
		case ok := <-out:
			fmt.Println(ok)
		}
	}
}
