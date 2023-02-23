package main

import (
	"github.com/hktalent/ProScan4all/lib/Smuggling"
	"github.com/hktalent/ProScan4all/lib/util"
	"os"
	"testing"
)

func TestGetIp(t *testing.T) {
	os.Setenv("CacheName", "TmpXx1")
	util.DoInit(nil)
	//t.Run("获取当前用户的ip", func(t *testing.T) {
	//	if got := util.GetIp(); !reflect.DeepEqual(got, "") {
	//		t.Errorf("GetIp() = %v, want %v", got, "")
	//	}
	//})

	Smuggling.DoCheckSmuggling("http://127.0.0.1/", "")
	util.Wg.Wait()
	util.CloseAll()
}
