package giop

import "fmt"

func Log(i int, s string) {
	fmt.Printf("[*] id=%d %s\n", i, s)
}
