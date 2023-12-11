package subfinder

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"os"
	"runtime"
	"strings"
)

func DoSubfinder(a []string, out chan string, done chan bool) {
	defer func() {
		done <- true
		close(out)
		close(done)
	}()
	if nil == a || 0 == len(a) {
		return
	}
	szCmd := "subfinder"
	szP := util.SzPwd + "/config/"
	os.MkdirAll(szP+"tools/"+runtime.GOOS, os.ModePerm)
	a1 := []string{
		szP + "tools/" + runtime.GOOS + "/" + szCmd,
		"-all", "-silent", "-nc",
	}
	if nil != util.G_Options {
		if m1, ok := util.G_Options.(map[string]interface{}); ok {
			if b, ok2 := m1["JSON"]; ok2 {
				if isJ, ok1 := b.(bool); ok1 && isJ {
					a = append(a, "-json")
				}
			}
		}
	}
	if fT := util.GetTempFile(szCmd); nil != fT {
		fT.Write([]byte(strings.Join(a, "\n")))
		fT.Close()
		defer os.Remove(fT.Name())
		a1 = append(a1, "-dL", fT.Name())
		if s, err := util.DoCmd(a1...); "" != s && nil == err {
			util.Writeoutput(s)
			a2 := strings.Split(strings.ToLower(s), "\n")
			for _, x := range a2 {
				x = strings.TrimSpace(x)
				if "" != x {
					out <- x
				}
			}
			return
		}
	}
}
