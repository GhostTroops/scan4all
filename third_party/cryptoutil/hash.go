package cryptoutil

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256Sum(data interface{}) string {
	hasher := sha256.New()
	if v, ok := data.([]byte); ok {
		hasher.Write(v)
	} else if v, ok := data.(string); ok {
		hasher.Write([]byte(v))
	} else {
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
