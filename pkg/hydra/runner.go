package hydra

import "log"

// 密码破解
func Start(IPAddr string, Port int, Protocol string) {
	authInfo := NewAuthInfo(IPAddr, Port, Protocol)
	crack := NewCracker(authInfo, false, 32)
	log.Println("[hydra]->开始对%v:%v[%v]进行暴力破解，字典长度为：%d", IPAddr, Port, Protocol, crack.Length())
	go crack.Run()
}
