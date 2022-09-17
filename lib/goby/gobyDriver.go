package goby

import (
	"embed"
	"fmt"
)

//go:embed goby_pocs
var GobyPocs embed.FS

// 驱动 Goby PoCs
func DoGobyGocks(szUrl string) {
	for poc := range LoadPocs(GobyPocs) {
		szPoc := fmt.Sprintf("%v", poc)
		if "" != szPoc {
		}
	}
}
