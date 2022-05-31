package fingerprint

import (
	_ "embed"
)

//go:embed dicts/localFinger.json
var localFinger string