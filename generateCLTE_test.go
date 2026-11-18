package main

import (
	"os"
	"testing"

	util "github.com/hktalent/go-utils"
)

func TestXain(t *testing.T) {
	if "" == os.Getenv("SCAN4ALL_TEST_CLTE") {
		t.Skip("手工用例，设置 SCAN4ALL_TEST_CLTE=1 后再运行")
	}
	util.DoInit(nil)
	//main2.Xain()
	util.Wg.Wait()
	util.CloseAll()
}
