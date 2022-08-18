package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	data, err := ioutil.ReadFile(os.Args[1])
	if nil == err {
		fmt.Printf("%x", data)
	} else {

		fmt.Printf("%v", err)
	}
}
