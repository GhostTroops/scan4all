package brute

import (
	_ "embed"
	"strings"
)

type userpass struct {
	username string
	password string
}

var (
	tomcatuserpass   = []userpass{}
	jbossuserpass    = []userpass{}
	top100pass       = []string{}
	weblogicuserpass = []userpass{}
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

func cvtUps(s string) []userpass {
	a := strings.Split(s, "\n")
	var aRst []userpass
	for _, x := range a {
		if x != "" {
			j := strings.Split(x, ",")
			if len(j) == 2 {
				aRst = append(aRst, []userpass{{j[0], j[1]}}...)
			}
		}
	}
	return aRst
}
func cvtLines(s string) []string {
	return strings.Split(s, "\n")
}

func init() {
	tomcatuserpass = cvtUps(szTomcatuserpass)
	jbossuserpass = cvtUps(szJbossuserpass)
	weblogicuserpass = cvtUps(szWeblogicuserpass)
	filedic = append(filedic, cvtLines(szFiledic)...)
	top100pass = append(top100pass, cvtLines(szTop100pass)...)
}
