package fingerprint

import (
	_ "embed"
	"github.com/hktalent/scan4all/pkg"
)

//go:embed dicts/eHoleFinger.json
var eHoleFinger string

func init() {
	eHoleFinger = pkg.GetVal4File("eHoleFinger", eHoleFinger)
}
