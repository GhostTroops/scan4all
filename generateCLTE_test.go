package main

import (
	main2 "github.com/hktalent/ProScan4all/lib/Smuggling/generate"
	util "github.com/hktalent/go-utils"
	"testing"
)

func TestXain(t *testing.T) {
	util.DoInit(nil)
	main2.Xain()
	util.Wg.Wait()
	util.CloseAll()
}
