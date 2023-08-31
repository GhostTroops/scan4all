package main

import (
	"embed"
	"fmt"
	"github.com/hktalent/scan4all/lib/api"
	"github.com/hktalent/scan4all/lib/util"
	_ "github.com/hktalent/scan4all/pkg/hydra"
	"github.com/hktalent/scan4all/pkg/xcmd"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
)

//go:embed config/*
var config embed.FS

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	//os.Args = []string{"", "-host", "http://127.0.0.1", "-v"}
	os.Args = []string{"", "-host", "https://127.0.0.1:2083", "-v"}
	//os.Args = []string{"", "-host", "https://www.sina.com.cn/", "-v", "-o", "xxx.csv"}
	//os.Args = []string{"", "-list", "list.txt", "-v"}
	//os.Args = []string{"", "-list", "./3ee8307c128be7296b2fa2ad5453341a3d37c2b6.xml", "-v"}

	runtime.GOMAXPROCS(runtime.NumCPU())
	util.DoInit(&config)

	// 初始化、下载相关工具
	xcmd.InitToolsFile()
	// set version
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		util.Version = buildInfo.Main.Version
	} else {
		Version = util.Version
	}

	szTip := ""
	if util.GetValAsBool("enableDevDebug") {
		// debug 优化时启用///////////////////////
		util.DefaultPool.Submit(func() {
			szTip = "Since you started http://127.0.0.1:6060/debug/pprof/ with -debug, close the program with: control + C"
			fmt.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n\ngo tool pprof -seconds=10 -http=:9999 http://localhost:6060/debug/pprof/heap")
			http.ListenAndServe(":6060", nil)
		})
		//////////////////////////////////////////*/
	}
	api.StartScan(nil)
	log.Printf("wait for all threads to end\n%s", szTip)
	util.Wg.Wait()
	util.CloseAll()
}
