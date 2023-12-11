package pocs_yml

import (
	"embed"
	"github.com/GhostTroops/scan4all/lib/util"
	xray_check "github.com/GhostTroops/scan4all/pocs_yml/check"
	common_structs "github.com/GhostTroops/scan4all/pocs_yml/pkg/common/structs"
	xray_requests "github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/requests"
	"github.com/GhostTroops/scan4all/pocs_yml/utils"
	"net/url"
	"time"
)

//go:embed ymlFiles
var Pocs embed.FS

func Check(target string, ceyeapi string, ceyedomain string, proxy string, pocname string) []string {
	u01, _ := url.Parse(target)
	if util.TestRepeat(u01.Host, ceyeapi, ceyedomain, proxy, pocname, "yml_poc_check") {
		return []string{}
	}
	//fmt.Println(u01.Host + " |||" + pocname)
	common_structs.InitReversePlatform(ceyeapi, ceyedomain)
	_ = xray_requests.InitHttpClient(10, proxy, time.Duration(5)*time.Second)
	xrayPocs := utils.LoadMultiPoc(Pocs, pocname)
	xrayTotalReqeusts := 0
	for _, poc := range xrayPocs {
		ruleLens := len(poc.Rules)
		if poc.Transport == "tcp" || poc.Transport == "udp" {
			ruleLens += 1
		}
		xrayTotalReqeusts += 1 * ruleLens
	}
	if xrayTotalReqeusts == 0 {
		xrayTotalReqeusts = 1
	}
	xray_requests.InitCache(xrayTotalReqeusts)
	return xray_check.Start(target, xrayPocs)
}
