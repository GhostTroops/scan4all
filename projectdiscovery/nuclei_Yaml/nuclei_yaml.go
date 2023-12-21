package nuclei_Yaml

import (
	"C"
	"bytes"
	"github.com/GhostTroops/scan4all/lib/util"
	"os"
	"runtime"
	"strings"
)

// https://stackoverflow.com/questions/70192715/qt-shared-c-library-exported-from-golang
// https://github.com/golang/go/issues/26204
/*
LIBS += -L$${PWD}\shared -lCalc
go build -buildmode c-shared -o calcLib.a calcLib.go
gcc -o calc.exe calc.c calcLib.a
go build -gccgoflags="-static-libgo" hello.go
*/
func RunNuclei(buf *bytes.Buffer) {
	s001 := strings.TrimSpace(buf.String())
	if nil == buf {
		return
	}
	a66 := strings.Split(s001, "\n")
	x55, _ := util.TestIsWeb(&a66)
	if nil == x55 || 0 == len(*x55) {
		return
	}
	szCmd := "nuclei"
	szP := util.SzPwd + "/config/"
	os.MkdirAll(szP+"tools/"+runtime.GOOS, os.ModePerm)
	a := []string{
		//szP + "tools/" + runtime.GOOS + "/" +
		szCmd,
		//"-t", szP + "nuclei-templates",
		"-sa",
		"-duc", "-silent", "-nc",
	}
	if nil != util.G_Options {
		if m1, ok := util.G_Options.(map[string]interface{}); ok {
			if b, ok2 := m1["JSON"]; ok2 {
				if isJ, ok1 := b.(bool); ok1 && isJ {
					a = append(a, "-j")
				}
			}
		}
	}
	if fT := util.GetTempFile(szCmd); nil != fT {
		fT.Write([]byte(strings.Join(*x55, "\n")))
		fT.Close()
		defer os.Remove(fT.Name())
		a = append(a, "-l", fT.Name())
		if s, err := util.DoCmd(a...); "" != s && nil == err {
			util.Writeoutput(s)
		}
	}
}
