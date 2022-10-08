package main

import (
	"github.com/hktalent/ProScan4all/engine"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pkg/portScan"
	"github.com/hktalent/goSqlite_gorm/lib"
	"github.com/hktalent/goSqlite_gorm/lib/scan/Const"
	"net/http"
	"time"
)

func main() {
	util.DoInit(nil)
	//util.InitModle(masscan.Ports{}, masscan.Address{}, masscan.Service{}, masscan.State{}, masscan.Host{})
	util.InitModle(&portScan.Ports{}, &portScan.Host{})
	<-time.After(3 * time.Second)
	engine.Dispather(&lib.Target4Chan{ScanWeb: "192.168.0.111", ScanType: Const.ScanType_Masscan})
	//portScan.MassScanTarget("192.168.0.111", "masscan1", []string{}, portScan.PortsStr("9200,8000"), portScan.TargetStr("2.168.0.111"))
	http.ListenAndServe(":6060", nil)
	util.Wg.Wait()
	util.CloseAll()
}
