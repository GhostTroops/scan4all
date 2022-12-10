package main

import (
	"github.com/hktalent/ProScan4all/lib/util"
	"reflect"
	"testing"
)

func TestGetIp(t *testing.T) {
	util.DoInit(nil)
	t.Run("获取当前用户的ip", func(t *testing.T) {
		if got := util.GetIp(); !reflect.DeepEqual(got, "") {
			t.Errorf("GetIp() = %v, want %v", got, "")
		}
	})
	util.Wg.Wait()
	util.CloseAll()
}
