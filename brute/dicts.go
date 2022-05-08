package brute

import (
	_ "embed"
	"strings"
)

type Userpass struct {
	username string
	password string
}

var (
	tomcatuserpass   = []Userpass{}
	jbossuserpass    = []Userpass{}
	top100pass       = []string{}
	weblogicuserpass = []Userpass{}
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

func CvtUps[T any](s string) []T {
	a := strings.Split(s, "\n")
	var aRst []T
	for _, x := range a {
		j := strings.Split(x, ",")
		aRst = append(aRst, T{j[0], j[1]})
	}
	return aRst
}
func CvtLines(s string) []string {
	return strings.Split(s, "\n")
}
func init() {
	tomcatuserpass = CvtUps[Userpass](szTomcatuserpass)
	jbossuserpass = CvtUps[Userpass](szJbossuserpass)
	weblogicuserpass = CvtUps[Userpass](szWeblogicuserpass)
	filedic = append(filedic, CvtLines(szFiledic)...)
	top100pass = append(top100pass, CvtLines(szTop100pass)...)
}
