package Funcs

import (
	Configs "github.com/GhostTroops/scan4all/webScan/config"
)

type extras struct {
	timeout_count map[string]int
	replace       string
}

var Extra extras

func Choose(urllist *[]string) {
	//timeout_count := make(map[string]int)
	Extra.timeout_count = make(map[string]int) //这个用来统计是否超过五次超时或失败，如果一个URL超过五次，则直接跳过该url

	if Configs.UserObject.AllJson == true {
		final_ALLurl_ALLJson(urllist)
	}
}
