package fingerprint

import (
	_ "embed"
	"github.com/hktalent/scan4all/pkg"
)

//go:embed dicts/localFinger.json
var localFinger string

func init() {
	localFinger = pkg.GetVal4File("localFinger", localFinger)
}
