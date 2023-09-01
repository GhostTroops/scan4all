//go:build darwin

package autofdmax

import "github.com/projectdiscovery/fdmax"

func init() {
	_ = fdmax.Set(fdmax.OSXMax)
}
