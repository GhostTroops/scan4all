package main

import (
	util "github.com/hktalent/go-utils"
	main2 "github.com/hktalent/scan4all/lib/Smuggling/generate"
	"testing"
)

func TestXain(t *testing.T) {
	util.DoInit(nil)
	main2.Xain()
	util.Wg.Wait()
	util.CloseAll()
}
