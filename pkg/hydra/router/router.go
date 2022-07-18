package router

import (
	"github.com/go-routeros/routeros"
)

// router os 密码破解
func RouterOSAuth(ip string, port string, user string, pass string) (result bool, err error) {
	result = false
	c, err1 := routeros.Dial(ip+":"+port, user, pass)
	if err1 == nil {
		result = true
	}

	defer c.Close()

	return result, err1
}
