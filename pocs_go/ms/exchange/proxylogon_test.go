package exchange

import "testing"

func TestDoCheck(t *testing.T) {
	t.Run("test DoCheck", func(t *testing.T) {
		DoCheck("http://192.168.10.53", "xx.mail")
	})

}
