package main

import (
	"github.com/GhostTroops/scan4all/pkg/common"
	"github.com/GhostTroops/scan4all/pkg/tools"
	util "github.com/hktalent/go-utils"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
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
	os.Args = append([]string{""}, strings.Split(`feed01.live-sec.co.jp
feed20.live-sec.co.jp
fx-m.himawari-group.co.jp
fx-sys.himawari-group.co.jp
fx-web-demo.himawari-group.co.jp
fx-web.himawari-group.co.jp
fxdemo-sys.himawari-group.co.jp
himawari-group.co.jp
itspdf.sc.mufg.jp
nctt.co.jp
nova.kiraboshi-ld-sec.co.jp:10443
off-exchange.jp
qn.sbineotrade.jp
sakidori.himawari-group.co.jp
snt02.sbineotrade.jp
snt04.sbineotrade.jp
tf1.himawari-group.co.jp
tosyodai5106.net
www.toho-sec.co.jp
www2.himawari-group.co.jp
210-129-52-158.newton.jp-east.compute.idcfcloud.net
clickcount.mizuho-sc.com
ec2-13-114-147-108.ap-northeast-1.compute.amazonaws.com
ec2-15-152-224-195.ap-northeast-3.compute.amazonaws.com
ec2-15-168-103-27.ap-northeast-3.compute.amazonaws.com
ec2-18-176-41-103.ap-northeast-1.compute.amazonaws.com`, "\n")...)
	common.DoCommontools(func(s string, wg1 *util.SizedWaitGroup) {
		log.Println(s)
		input <- &s
	})
	wg.Wait()
	util.CloseAll()
	util.Wg.Wait()
}
