package writer

import (
	osutil "github.com/projectdiscovery/utils/os"
)

var NewLine string

func init() {
	if osutil.IsWindows() {
		NewLine = "\r\n"
	} else {
		NewLine = "\n"
	}
}
