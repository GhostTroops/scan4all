package pocs_yml

import (
	"embed"
	xray_check "github.com/hktalent/scan4all/pocs_yml/check"
	common_structs "github.com/hktalent/scan4all/pocs_yml/pkg/common/structs"
	xray_requests "github.com/hktalent/scan4all/pocs_yml/pkg/xray/requests"
	"github.com/hktalent/scan4all/pocs_yml/utils"
	"time"
)

//go:embed ymlFiles
var Pocs embed.FS

func Check(target string, ceyeapi string, ceyedomain string, proxy string, pocname string) []string {
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
