package tools

import (
	. "github.com/GhostTroops/scan4all/pkg/utils"
	util "github.com/hktalent/go-utils"
	"net/url"
	"strings"
)

// 根据 k 转换 出对应的数字类型
func GetType(k string) int {
	nR := 1
	switch k {
	case Ipgs:
		nR = 0
	case Ksubdomain:
		nR = 3
	case Httpx:
		nR = 1
	case Tlsx:
		nR = 1
	case Nuclei:
		nR = 1
	case Gopoc:
		nR = 1
	case Filefuzz:
		nR = 1
	}
	return nR
}

/*
将 s 按 n 类型 转换 返回
0 host
1 标准 url
2 主机 所有ip 基于 \n 分割
3、host:port
4、表示输入 是 masscan xml line
*/
func GetInput(s string, n int) string {
	oU, err := url.Parse(s)
	switch n {
	case 0:
		if nil == err {
			return oU.Host
		}
		return ""
	case 3:
		if nil == err {
			return oU.Hostname()
		}
		return ""
	case 1:
		if nil == err { // 标准 url
			return oU.String()
		}
		return ""
	case 2:
		if nil == err {
			return strings.Join(util.GetIps(oU.Hostname()), "\n")
		}
		return ""
	}

	return ""
}
