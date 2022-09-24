package main

import (
	"embed"
	"fmt"
	"github.com/hktalent/scan4all/lib/api"
	"github.com/hktalent/scan4all/lib/util"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
)

//go:embed config/*
var config embed.FS

func main() {
	//os.Args = []string{"", "-host", "http://127.0.0.1"}
	runtime.GOMAXPROCS(runtime.NumCPU())
	util.DoInit(&config)
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
	util.CloseAll()
}
