package portScan

import (
	"log"
	"testing"
)

func TestAsynCmd(t *testing.T) {
	t.Run("async cmd", func(t *testing.T) {
		x1 := &Scanner{Targets: []string{"127.0.0.1"}, Ports: []string{"0-65535"}}
		var streams []*Stream
		_, err := x1.Scan(func(s *Stream) {
			streams = append(streams, s)
		})
		if nil != err {
			log.Println("nmap scan is error ", err)
		}
	})
}
