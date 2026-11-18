package util

import (
	"os"
	"testing"
)

func TestSendReq(t *testing.T) {
	if "" == os.Getenv("SCAN4ALL_TEST_ES") {
		t.Skip("需要可用的 Elasticsearch，设置 SCAN4ALL_TEST_ES=1 后再运行")
	}
	DoInit(nil)
	t.Run("sv2es", func(t *testing.T) {
		SendReq(`{"xx":"sdfsf"}`, "xx01nmap", Nmap)
	})
	Wg.Wait()
	CloseAll()
}
