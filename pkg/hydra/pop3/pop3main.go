package pop3

import (
	"github.com/hktalent/scan4all/lib/util"
	"log"
	"strings"
)

func getConn(address string) *Conn {
	o := util.GetCache(address, true)
	if nil != o {
		return o.(*Conn)
	}
	x1 := Opt{
		Host:       address,
		Port:       995,
		TLSEnabled: true,
		//Port:       110,
		//TLSEnabled: false,
	}
	if strings.HasSuffix(address, ":110") {
		x1.TLSEnabled = false
		x1.Port = 110
	}
	p := New(x1)
	c, err := p.NewConn()
	if err != nil {
		log.Printf("%v", err)
		return nil
	}
	util.RegDelayCbk(address, func() {
		c.Quit()
	}, func() interface{} {
		return c
	}, 0, 10)
	return c
}

// pop3密码破解
//  优化 pop3、pop3s 密码破解算法，每个目标相同端口，多个密码破解复用一次网络链接，提高破解效率
func DoPop3(address, user, pass string) bool {
	c := getConn(address)
	// Authenticate.
	if err := c.Auth(user, pass); err != nil {
		return false
	}
	util.DoNow(address)
	return true
}
