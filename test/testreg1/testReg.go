package main

import (
	"context"
	_ "embed"
	"github.com/GhostTroops/scan4all/lib/util"
)

// 测试正则表达式是否正确
func main() {
	// 中途控制关闭当前目标所有fuzz
	_, stop := context.WithCancel(util.Ctx_global)
	stop()
	stop()
	stop()
	stop()

}
