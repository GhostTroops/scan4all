package util

import "testing"

func TestSendReq(t *testing.T) {
	DoInit(nil)
	t.Run("sv2es", func(t *testing.T) {
		SendReq("test", "nmap", Nmap)
	})
	Wg.Wait()
	CloseAll()
}
