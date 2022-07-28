package goby

import "embed"

//go:embed goby_pocs
var GobyPocs embed.FS

// 驱动 Goby PoCs
func DoGobyGocks(szUrl string) {
	for poc := range LoadPocs(GobyPocs) {
		if "" != poc {
		}
	}
}
