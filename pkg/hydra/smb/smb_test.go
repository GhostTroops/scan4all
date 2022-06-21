package smb

import (
	"fmt"
	"testing"
)

func TestCheck(t *testing.T) {
	ok, err := Check("192.168.0.2", "administrator", "workgroup", "123456", 445)
	fmt.Println(ok, err)
}
