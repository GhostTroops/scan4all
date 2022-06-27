package brute

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

// weblogic默认的登陆尝试次数为5次，5次失败则weblogic用户锁定，即使你已经找到正确的密码，也不能登陆到console；默认的锁定时间为30分钟
// 后期再优化间隔35分钟后继续后面的密码
func Weblogic_brute(url string) (username string, password string) {
	if req, err := pkg.HttpRequset(url+"/console/login/LoginForm.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			for uspa := range weblogicuserpass {
				if req2, err2 := pkg.HttpRequset(url+"/console/j_security_check", "POST", fmt.Sprintf("j_username=%s&j_password=%s", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password), true, nil); err2 == nil {
					if pkg.StrContains(req2.RequestUrl, "console.portal") {
						pkg.BurteLog(fmt.Sprintf("Found vuln Weblogic password|%s:%s|%s\n", weblogicuserpass[uspa].username, weblogicuserpass[uspa].password, url+"/console/"))
						return weblogicuserpass[uspa].username, weblogicuserpass[uspa].password
					}
				}
			}
			return "login_page", ""
		}
	}
	return "", ""
}
