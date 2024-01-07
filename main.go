package main

import (
	"github.com/GhostTroops/scan4all/pkg/common"
	"github.com/GhostTroops/scan4all/pkg/tools"
	util "github.com/hktalent/go-utils"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

func main() {
	//os.Unsetenv("HTTPS_PROXY")
	//os.Unsetenv("HTTP_PROXY")
	util.DoInitAll()
	go func() {
		//szTip = "Since you started http://127.0.0.1:6060/debug/pprof/ with -debug, close the program with: control + C"
		log.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n\ngo tool pprof -seconds=10 -http=:9999 http://localhost:6060/debug/pprof/heap")
		http.ListenAndServe(":6060", nil)
	}()

	var input = make(chan *string)
	defer close(input)
	var wg = util.NewSizedWaitGroup(0)
	util.DoSyncFunc(func() {
		tools.DoCmds(input, 0, &wg)
	})
	os.Args = []string{"", "https://www.sina.com.cn/"}
	common.DoCommontools(func(s string, wg1 *util.SizedWaitGroup) {
		input <- &s
	})
	wg.Wait()
	util.CloseAll()
	util.Wg.Wait()
}
