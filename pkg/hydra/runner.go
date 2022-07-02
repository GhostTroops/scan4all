package hydra

import (
	"encoding/json"
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"github.com/logrusorgru/aurora"
	"log"
	"strings"
)

func init() {
	InitDefaultAuthMap()
	var a1, a2 []string
	HydraUser := pkg.GetVal4File("HydraUser", "")
	if "" != HydraUser {
		a1 = strings.Split(HydraUser, "\n")
	}

	HydraPass := pkg.GetVal4File("HydraPass", "")
	if "" != HydraPass {
		a2 = strings.Split(HydraPass, "\n")
	}
	//加载自定义字典
	InitCustomAuthMap(a1, a2)
}

// 密码破解
func Start(IPAddr string, Port int, Protocol string) {
	authInfo := NewAuthInfo(IPAddr, Port, Protocol)
	crack := NewCracker(authInfo, true, 128)
	fmt.Printf("\n[hydra]->开始对%v:%v[%v]进行暴力破解，字典长度为：%d\n", IPAddr, Port, Protocol, crack.Length())
	go crack.Run()
	//爆破结果获取
	var out AuthInfo
	for info := range crack.Out {
		out = info
	}
	if nil != &out {
		pkg.SendAData[AuthInfo](fmt.Sprintf("%s:%d", out.IPAddr, out.Port), []AuthInfo{out}, "hydra")
		data, _ := json.Marshal(out)
		log.Println("成功密码破解：", aurora.BrightRed(string(data)))
		log.Printf("\n[hydra]-> %v:%v[%v]暴力破解 Finish\n", IPAddr, Port, Protocol)
	}

	//crack.Pool.Wait()
}
