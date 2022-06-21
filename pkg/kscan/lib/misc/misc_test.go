package misc

import (
	"fmt"
	"testing"
)

func TestName(t *testing.T) {
	fmt.Println(First2Upper("acBCDSFdsdsfsa"))
}

func TestFixLine(t *testing.T) {

	var s = "1 1  1          1"
	fmt.Println(s)
	fmt.Println(FixLine(s))

}
