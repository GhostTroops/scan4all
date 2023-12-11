package main

import (
	"github.com/GhostTroops/scan4all/lib/Smuggling"
	"github.com/GhostTroops/scan4all/lib/util"
	"os"
	"testing"
)

func TestGetIp(t *testing.T) {
	os.Setenv("CacheName", "TmpXx1")
	os.Setenv("HTTPS_PROXY", "socks5://127.0.0.1:7890")
	util.DoInit(nil)
	//t.Run("获取当前用户的ip", func(t *testing.T) {
	//	if got := util.GetIp(); !reflect.DeepEqual(got, "") {
	//		t.Errorf("GetIp() = %v, want %v", got, "")
	//	}
	//})

	Smuggling.DoCheckSmuggling("https://ttblaze.iifl.com:4021/", "")
	util.Wg.Wait()
	util.CloseAll()
}
