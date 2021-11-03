package pocs_yml

import (
	"embed"
	xray_check "github.com/veo/vscan/pocs_yml/check"
	common_structs "github.com/veo/vscan/pocs_yml/pkg/common/structs"
	xray_requests "github.com/veo/vscan/pocs_yml/pkg/xray/requests"
	"github.com/veo/vscan/pocs_yml/utils"
	"time"
)

//go:embed ymlFiles
var Pocs embed.FS

func Check(target string, ceyeapi string, ceyedomain string, proxy string, pocname string) {
	common_structs.InitCeyeApi(ceyeapi, ceyedomain)
	_ = xray_requests.InitHttpClient(10, proxy, time.Duration(5)*time.Second)
	xrayPocs := utils.LoadMultiPoc(Pocs, pocname)
	xray_check.Start(target, xrayPocs)
}
