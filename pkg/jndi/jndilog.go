package jndi

import (
	"encoding/hex"
	"strings"
)

func Jndilogchek(randomstr string) bool {
	if JndiLog == nil {
		return false
	}
	for _, log := range JndiLog {
		HexRandomstr := hex.EncodeToString([]byte(randomstr))
		if strings.Contains(log, HexRandomstr) {
			return true
		}
	}
	return false
}
