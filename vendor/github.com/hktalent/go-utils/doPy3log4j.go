package go_utils

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

var log4jsv sync.Map

// 1、检测 $HOME/MyWork/log4j-scan 存在就执行 python3 版本log4j检测
// 2、相同目标只执行一次，基于内存缓存
// 3、只支持：https://github.com/hktalent/log4j-scan 版本
func DoLog4j(szUrl string) {
	if 5 > len(szUrl) || !FileExists(UserHomeDir+"/MyWork/log4j-scan") {
		//fmt.Println("DoLog4j: ", 5 > len(szUrl), !FileExists(UserHomeDir+"/MyWork/log4j-scan"))
		return
	}
	DoSyncFunc(func() {
		if "" == EsUrl {
			EsUrl = GetValByDefault("esUrl", "http://127.0.0.1:9200/%s_index/_doc/%s")
		}
		oUrl, err := url.Parse(fmt.Sprintf(strings.TrimSpace(EsUrl),"x","x"))
		if nil == err {
			p1, err := os.Getwd()
			if nil == err {
				szU1 := oUrl.Scheme + "://" + oUrl.Host
				if _, ok := log4jsv.Load(szU1); !ok {
					log4jsv.Store(szU1, true)
					if "http" != strings.ToLower(szUrl[0:4]) {
						szUrl = "http://" + szUrl
					}
					DoCmd(p1+"/config/doPy3log4j.sh", szUrl, szU1)
				}
			}
		}
	})
}
