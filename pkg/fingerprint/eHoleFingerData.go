package fingerprint

import (
	_ "embed"
	"github.com/hktalent/ProScan4all/lib/util"
)

//go:embed dicts/eHoleFinger.json
var eHoleFinger string

func init() {
	util.RegInitFunc(func() {
		eHoleFinger = util.GetVal4File("eHoleFinger", eHoleFinger)
	})
}
