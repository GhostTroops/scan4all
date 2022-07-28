package main

import (
	"embed"
	"fmt"
	"github.com/hktalent/scan4all/lib/api"
	"github.com/hktalent/scan4all/lib/util"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sync"
	"time"
)

//go:embed config/*
var config embed.FS

func init() {
	util.Init2(&config)
	rand.Seed(time.Now().UnixNano())
}

var Wg sync.WaitGroup

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	util.Wg = &Wg
	defer func() {
		util.Cache1.Close()
		if runtime.GOOS == "windows" || util.GetValAsBool("autoRmCache") {
			os.RemoveAll(util.GetVal(util.CacheName))
		}
		// clear
		// 程序都结束了，没有必要清理内存了
		// fingerprint.ClearData()
	}()
	szTip := ""
	if util.GetValAsBool("enablDevDebug") {
		// debug 优化时启用///////////////////////
		go func() {
			szTip = "Since you started http://127.0.0.1:6060/debug/pprof/ with -debug, close the program with: control + C"
			fmt.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n\ngo tool pprof -seconds=10 -http=:9999 http://localhost:6060/debug/pprof/heap")
			http.ListenAndServe(":6060", nil)
		}()
		//////////////////////////////////////////*/
	}
	api.StartScan(nil)

	log.Printf("wait for all threads to end\n%s", szTip)
	util.Wg.Wait()
	util.StopAll()
}
