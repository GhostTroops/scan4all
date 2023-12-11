package brute

import (
	_ "embed"
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

type UserPass struct {
	username string
	password string
}

var (
	tomcatuserpass   = []UserPass{} // tomcat user pass 字典
	jbossuserpass    = []UserPass{} // jboss user pass 字典
	top100pass       = []string{}   // top 100 密码，用于 http爆破
	weblogicuserpass = []UserPass{} // weblogic user pass 字典
	filedic          = []string{}   // fuzz字典
	SelfHd           = []string{}
)

// by waf
//
//go:embed dicts/selfHd.txt
var selfHds string

// http 爆破user
//
//go:embed dicts/httpuser.txt
var httpuser string

// http 爆破密码字典
//
//go:embed dicts/httpass.txt
var httpass string

//go:embed dicts/tomcatuserpass.txt
var szTomcatuserpass string

//go:embed dicts/jbossuserpass.txt
var szJbossuserpass string

//go:embed dicts/weblogicuserpass.txt
var szWeblogicuserpass string

//go:embed dicts/filedic.txt
var szFiledic string

//go:embed dicts/top100pass.txt
var szTop100pass string

func CvtUps(s string) []UserPass {
	a := strings.Split(s, "\n")
	var aRst []UserPass
	for _, x := range a {
		x = strings.TrimSpace(x)
		if "" == x {
			continue
		}
		j := strings.Split(x, ",")
		if 1 < len(j) {
			aRst = append(aRst, UserPass{username: j[0], password: j[1]})
		}
	}
	return aRst
}
func CvtLines(s string) []string {
	return strings.Split(s, "\n")
}

// http 密码爆破user
var basicusers []string

func init() {
	util.RegInitFunc(func() {
		SelfHd = append(SelfHd, CvtLines(util.GetVal4File("SelfHd", selfHds))...)
		tomcatuserpass = CvtUps(util.GetVal4File("tomcatuserpass", szTomcatuserpass))
		jbossuserpass = CvtUps(util.GetVal4File("jbossuserpass", szJbossuserpass))
		weblogicuserpass = CvtUps(util.GetVal4File("weblogicuserpass", szWeblogicuserpass))
		filedic = append(filedic, CvtLines(util.GetVal4File("filedic", szFiledic))...)
		top100pass = append(top100pass, CvtLines(util.GetVal4File("top100pass", szTop100pass))...)
		basicusers = strings.Split(strings.TrimSpace(util.GetVal4File("httpuser", httpass)), "\n")
		top100pass = append(top100pass, strings.Split(strings.TrimSpace(util.GetVal4File("httpass", httpass)), "\n")...)
	})
}

func ByWafHd(m1 *map[string]string) *map[string]string {
	if util.GetValAsBool("enableByWaf") {
		sz127 := "127.0.0.1"
		for _, k := range SelfHd {
			(*m1)[k] = sz127
		}
	}
	return m1
}
