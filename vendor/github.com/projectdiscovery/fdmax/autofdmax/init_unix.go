//go:build linux || openbsd || netbsd

package autofdmax

import (
	"github.com/projectdiscovery/fdmax"
)

func init() {
	_ = fdmax.Set(fdmax.UnixMax)
}
