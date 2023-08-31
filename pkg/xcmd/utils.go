package xcmd

import (
	"bytes"
	"fmt"
	"github.com/hktalent/kvDb"
	"github.com/hktalent/scan4all/lib/util"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var Pwd = ""
var ToolsPath = ""
var KvDb1 = kvDb.NewKvDb("db/51pwnCc", nil)
var envParm = map[string]string{}

func init() {
	rand.Seed(time.Now().UnixNano())
	util.RegInitFunc(func() {
		Pwd, _ = os.Getwd()
		ToolsPath = Pwd + "/tools/"
		envParm["PWD"] = Pwd
	})
}

func GetTempFile() (string, *os.File) {
	if tempInput, err := ioutil.TempFile("", "51pwnScan-*"); nil == err {
		defer tempInput.Close()
		return tempInput.Name(), tempInput
	}
	return "", nil
}

// 目标转换到target
func Target2HostsFile(s string) string {
	return DoTmpTargetFile(s, func(i *os.File) {
		if a := strings.Split(s, "\n"); 0 < len(a) {
			for _, x := range a {
				x = strings.TrimSpace(x)
				// 1.1.1.1
				if 7 > len(x) {
					continue
				}
				// url 的时候只处理host
				if strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") {
					if oU, err := url.Parse(x); nil == err {
						fmt.Fprintf(i, "%s\n", strings.Split(oU.Host, ":")[0])
					}
				} else {
					fmt.Fprintf(i, "%s\n", strings.Split(x, ":")[0])
				}
			}
		}
	})
}

var r002 = regexp.MustCompile(`(^www\.)|(^[\.\*]*)`)

// 目标转换到target
func Target4SubDomainNoFile(s string) string {
	var a1 []string
	if a := strings.Split(s, "\n"); 0 < len(a) {
		for _, x := range a {
			x = strings.TrimSpace(x)
			// a.x
			if 3 > len(x) {
				continue
			}
			x = ReplaceAll(r002, x, "")
			// url 的时候只处理host
			if strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") {
				if oU, err := url.Parse(x); nil == err {
					a1 = append(a1, fmt.Sprintf("%s", strings.Split(ReplaceAll(r002, oU.Host, ""), ":")[0]))
				}
			} else {
				a1 = append(a1, fmt.Sprintf("%s", strings.Split(x, ":")[0]))
			}
		}
	}
	return strings.Join(a1, ",")
}

func Target2Hosts4Fuzz(s, fuzz string) string {
	return DoTmpTargetFile(s, func(i *os.File) {
		if a := strings.Split(s, "\n"); 0 < len(a) {
			for _, x := range a {
				x = strings.TrimSpace(x)
				// a.x
				if 10 > len(x) {
					continue
				}
				fmt.Fprintf(i, "%s%s\n", fuzz, x)
			}
		}
	})
}

// 目标转换到target
func Target2Hosts4SubDomain(s string) string {
	return DoTmpTargetFile(s, func(i *os.File) {
		if a := strings.Split(s, "\n"); 0 < len(a) {
			for _, x := range a {
				x = strings.TrimSpace(x)
				// a.x
				if 3 > len(x) {
					continue
				}
				x = ReplaceAll(r002, x, "")
				// url 的时候只处理host
				if strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") {
					if oU, err := url.Parse(x); nil == err {
						fmt.Fprintf(i, "%s\n", strings.Split(ReplaceAll(r002, oU.Host, ""), ":")[0])
					}
				} else {
					fmt.Fprintf(i, "%s\n", strings.Split(x, ":")[0])
				}
			}
		}
	})
}

func TargetRaw2HostsFile(s string) string {
	return DoTmpTargetFile(s, func(i *os.File) { io.Copy(i, strings.NewReader(s)) })
}

func DoTmpTargetFile(s string, fnCbk func(*os.File)) string {
	tempInput, err := os.Create(fmt.Sprintf("%s%s%d", os.TempDir(), util.GetSha1(s), rand.Intn(int(time.Now().UnixNano()))))
	szName := tempInput.Name()
	if nil != err {
		log.Println(err)
		return ""
	}
	//szName, tempInput := GetTempFile()
	if nil != tempInput {
		defer tempInput.Close()
		fnCbk(tempInput)
		return szName
	}
	return ""
}

// 最佳的方法是将命令写到临时文件，并通过bash进行执行
func DoCmd(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // 标准输出
	cmd.Stderr = &stderr // 标准错误
	err := cmd.Run()
	outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
	// out, err := cmd.CombinedOutput()
	if nil != err {
		return "", err
	}
	return outStr + "\n" + errStr, err
}

func GetCmdParms(n string) []string {
	if o := util.GetAsAny("cmds"); nil != o {
		if a, ok := o.(map[string]interface{}); ok {
			if p, ok := a[n]; ok {
				if a1, ok := p.([]interface{}); ok {
					var a []string
					for _, i := range a1 {
						a = append(a, fmt.Sprintf("%v", i))
					}
					return a
				}
			}
		}
	}
	return nil
}

var r001 = regexp.MustCompile(`\{([^\}]+)\}`)

func ReplaceAll(r *regexp.Regexp, s, r1 string) string {
	return r.ReplaceAllString(s, r1)
	//return string(r.ReplaceAll([]byte(s), []byte(r1)))
}

func DoParms(a ...string) []string {
	for i, s := range a {
		if strings.Contains(s, "{") {
			if a1 := r001.FindStringSubmatch(s); 0 < len(a1) {
				if s1, ok := envParm[a1[1]]; ok {
					a[i] = ReplaceAll(r001, s, s1)
				}
			}
		}
	}
	return a
}
