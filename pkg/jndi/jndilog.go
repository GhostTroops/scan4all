package jndi

import (
	"encoding/hex"
	"github.com/hktalent/scan4all/pkg"
)

func Jndilogchek(randomstr string) bool {
	if JndiLog == nil {
		return false
	}
	for _, log := range JndiLog {
		HexRandomstr := hex.EncodeToString([]byte(randomstr))
		if pkg.StrContains(log, HexRandomstr) {
			return true
		}
	}
	return false
}
