package tools

import (
	"github.com/GhostTroops/scan4all/pkg/option"
	"github.com/GhostTroops/scan4all/pkg/utils"
	util "github.com/hktalent/go-utils"
)

func DoNuclei(wg *util.SizedWaitGroup, iptTmp chan *string, szCmdExt string) {
	if node := option.GetCmdNode4key(utils.Nuclei); nil != node {
		cmd2 := util.CloneObj[option.Cmd](node)
		cmd2.Cmd += " " + szCmdExt
		DoNodeCmd(cmd2, iptTmp, wg, true)
	}
}

// 获取指纹信息
func GetInfo(wg *util.SizedWaitGroup, iptTmp chan *string) {
	DoNuclei(wg, iptTmp, "-ept dns,file,headless,tcp,code,javascript -tags info")
}
