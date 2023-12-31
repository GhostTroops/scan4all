package main

import (
	"github.com/GhostTroops/scan4all/pkg/tools"
	util "github.com/hktalent/go-utils"
	"log"
)

func main() {
	//os.Unsetenv("HTTPS_PROXY")
	//os.Unsetenv("HTTP_PROXY")
	util.DoInitAll()
	var input = make(chan *string)
	util.DoSyncFunc(func() {
		tools.DoCmds(input, 0)
	})
	s := "https://www.paypal.com/"
	input <- &s
	util.Wg.Wait()
	log.Println("close input")
	util.CloseAll()
}
