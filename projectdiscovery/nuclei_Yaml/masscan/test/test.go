package main

import (
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/projectdiscovery/nuclei_Yaml/masscan"
)

func main() {
	//util.InitModle(masscan.Ports{}, masscan.Address{}, masscan.Service{}, masscan.State{}, masscan.Host{})
	util.InitModle(&masscan.Ports{}, &masscan.Host{})
	masscan.ScanTarget("192.168.0.111")
}
