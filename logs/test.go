package main

import (
	"fmt"
	"strings"
)

func main() {
	i := "Cookie: xxx"

	n := strings.Index(i, ":")
	fmt.Println(i[:n], i[n+1:])
}
