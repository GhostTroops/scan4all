package main

import (
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/projectdiscovery/nuclei_Yaml/masscan"
)

func main() {
	m := &masscan.Host{}
	util.InitModle(m)
	masscan.ScanTarget("192.168.0.111")
}
