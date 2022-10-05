package util

import (
	"log"
	"testing"
)

func TestAsynCmd(t *testing.T) {
	t.Run("async cmd", func(t *testing.T) {
		if err := AsynCmd(func(line string) {
			log.Println(line)
			// }, "/usr/local/bin/masscan", "--max-rate", "5000", "--rate", "5000", "-p", "0-65535", "-oX", "-", "127.0.0.1"); err != nil {
			// }, "/bin/bash", "-i", "/Users/51pwn/MyWork/scan4all/doNmapScan.sh", "127.0.0.1"); err != nil {
		}, "/bin/bash", "-i", "/Users/51pwn/MyWork/scan4all/doNmapScan.sh", "127.0.0.1"); err != nil {
			log.Println("err ", err)
		}
	})
}
