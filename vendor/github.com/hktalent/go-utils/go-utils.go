package go_utils

import (
	"embed"
	"sync"
)

//go:embed config/*
var config embed.FS

// 这个方法必须显示 调用
// 否则可能会在其他init之前调用，导致初始化失效
func DoInitAll() {
	Wg = &sync.WaitGroup{}
	DoInit(&config)
}
