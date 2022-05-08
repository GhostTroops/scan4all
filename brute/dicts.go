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

func cvtUps[T any](s string) []T {
	a := strings.Split(s, "\n")
	var aRst []T
	for _, x := range a {
		j := strings.Split(x, ",")
		aRst = append(aRst, T{j[0], j[1]})
	}
	return aRst
}
func cvtLines(s string) []string {
	return strings.Split(s, "\n")
}

func init() {
	tomcatuserpass = cvtUps[userpass](szTomcatuserpass)
	jbossuserpass = cvtUps[userpass](szJbossuserpass)
	weblogicuserpass = cvtUps[userpass](szWeblogicuserpass)
	filedic = append(filedic, cvtLines(szFiledic)...)
	top100pass = append(top100pass, cvtLines(szTop100pass)...)
}
