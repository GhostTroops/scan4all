package main

import (
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pkg/portScan"
)

func main() {
	//util.InitModle(masscan.Ports{}, masscan.Address{}, masscan.Service{}, masscan.State{}, masscan.Host{})
	util.InitModle(&portScan.Ports{}, &portScan.Host{})
	portScan.ScanTarget("192.168.0.111")
}
