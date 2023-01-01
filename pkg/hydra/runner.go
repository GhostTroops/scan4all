package hydra

import (
	"fmt"
	"github.com/hktalent/51pwnPlatform/lib/scan/Const"
	"github.com/hktalent/51pwnPlatform/pkg/models"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pkg"
	"github.com/logrusorgru/aurora"
	"log"
	"strconv"
	"strings"
)

func init() {
	util.RegInitFunc(func() {
		InitDefaultAuthMap()
		var a1, a2 []string
		HydraUser := util.GetVal4File("HydraUser", "")
		if "" != HydraUser {
			a1 = strings.Split(HydraUser, "\n")
		}

		HydraPass := util.GetVal4File("HydraPass", "")
		if "" != HydraPass {
			a2 = strings.Split(HydraPass, "\n")
		}
		//加载自定义字典
		InitCustomAuthMap(a1, a2)
		// util.EngineFuncFactory(Const.ScanType_WeakPassword, func(evt *models.EventData, args ...interface{}) {
		util.EngineFuncFactory(Const.ScanType_Pswd4hydra, func(evt *models.EventData, args ...interface{}) {
			if pkg.Contains(ProtocolList, evt.EventData[2].(string)) {
				Start(evt.EventData[0].(string), evt.EventData[1].(int), evt.EventData[2].(string))
			}
		})
	})
}

// 密码破解
func Start(IPAddr string, Port int, Protocol string) {
	authInfo := NewAuthInfo(IPAddr, Port, Protocol)
	nT, err := strconv.Atoi(util.GetVal4File("hydrathread", "64"))
	if nil != err {
		nT = 64
	}
	crack := NewCracker(authInfo, true, nT)
	fmt.Printf("\n[hydra]->开始对%v:%v [ %v ] 进行暴力破解，字典长度为：%d\n", IPAddr, Port, Protocol, crack.Length())
	go crack.Run()
	//爆破结果获取
	var out AuthInfo
	for info := range crack.Out {
		out = info
		if nil != &out && "" != out.Protocol && out.IPAddr != "" && "" != out.Auth.Username {
			util.SendAData[AuthInfo](fmt.Sprintf("%s:%d", out.IPAddr, out.Port), []AuthInfo{out}, util.Hydra)
			data, _ := util.Json.Marshal(out)
			fmt.Println("Successful password cracking：", aurora.BrightRed(string(data)))
		}
	}
	log.Printf("\n[hydra]-> %v:%v [ %v ] 暴力破解 Finish\n", IPAddr, Port, Protocol)
	//crack.Pool.Wait()
}
