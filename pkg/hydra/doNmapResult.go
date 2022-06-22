package pkg

import (
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/hktalent/scan4all/pkg/hydra"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// 弱口令检测
func CheckWeakPassword(ip, service string, port int) {
	// 在弱口令检测范围就开始检测，结果....
	if Contains(hydra.ProtocolList, strings.ToLower(service)) {
		hydra.Start(ip, port, service)
	}
}

func DoParseXml(s string) {
	doc, err := xmlquery.Parse(strings.NewReader(s))
	if err != nil {
		log.Println(err)
		return
	}
	for i, n := range xmlquery.Find(doc, "//item/title") {
		fmt.Printf("#%d %s\n", i, n.InnerText())
	}
}

func DoNmapRst() {
	if x1, ok := TmpFile[Naabu]; ok {
		for _, x := range x1 {
			defer func(r *os.File) {
				r.Close()
				os.RemoveAll(r.Name())
			}(x)
			b, err := ioutil.ReadFile(x.Name())
			if nil == err && 0 < len(b) {
				//log.Println("read config file ok: ", s)
				go DoParseXml(string(b))
			}
		}
	}
}
