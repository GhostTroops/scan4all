package brute

import (
	_ "embed"
	"strings"
)

type UserPass struct {
	username string
	password string
}

var (
	tomcatuserpass   = []UserPass{}
	jbossuserpass    = []UserPass{}
	top100pass       = []string{}
	weblogicuserpass = []UserPass{}
	filedic          = []string{}
)

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
func init() {
	tomcatuserpass = CvtUps(szTomcatuserpass)
	jbossuserpass = CvtUps(szJbossuserpass)
	weblogicuserpass = CvtUps(szWeblogicuserpass)
	filedic = append(filedic, CvtLines(szFiledic)...)
	top100pass = append(top100pass, CvtLines(szTop100pass)...)
}