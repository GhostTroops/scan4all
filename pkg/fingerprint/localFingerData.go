package fingerprint

import (
	_ "embed"
	"github.com/hktalent/scan4all/lib/util"
)

//go:embed dicts/localFinger.json
var localFinger string

func init() {
	localFinger = util.GetVal4File("localFinger", localFinger)
}
