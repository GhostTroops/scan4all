package exchange

import (
	"os"
	"testing"
)

func TestDoCheck(t *testing.T) {
	if "" == os.Getenv("EXCHANGE_TARGET") {
		t.Skip("需要真实 Exchange 环境，设置 EXCHANGE_TARGET=<url> 后再运行")
	}
	t.Run("test DoCheck", func(t *testing.T) {
		DoCheck(os.Getenv("EXCHANGE_TARGET"), "xx.mail")
	})

}
