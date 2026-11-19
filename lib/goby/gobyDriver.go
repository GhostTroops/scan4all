package goby

import (
	_ "embed"
)

// GobyPocs 内嵌的 goby pocs 压缩包数据
//
//go:embed goby_pocs.zip
var GobyPocs []byte

// 驱动 Goby PoCs
func DoGobyGocks(szUrl string) {
	for poc := range LoadPocs(GobyPocs) {
		szPoc := poc
		if "" != szPoc {
			_ = szPoc
		}
	}
}

// GetGobyPocs 返回内嵌的 goby pocs 原始内容（zip 字节）
func GetGobyPocs() []byte {
	return GobyPocs
}
