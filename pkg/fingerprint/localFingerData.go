package fingerprint

import (
	_ "embed"
	"github.com/GhostTroops/scan4all/lib/util"
)

//go:embed dicts/localFinger.json
var localFinger string

func init() {
	util.RegInitFunc(func() {
		localFinger = util.GetVal4File("localFinger", localFinger)
	})
}
