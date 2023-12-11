package main

import (
	"github.com/GhostTroops/scan4all/pkg/portScan"
	"log"
	"strings"
)

func main() {
	xx := portScan.Scanner{Targets: []string{"192.168.0.111"}, Ports: strings.Split(`5001
5001
2222
445
873
3702
51417
8000
548
3000
8001
3260
111`, "\n")}
	_, err := xx.Scan(func(stream *portScan.Stream) {
		log.Printf("%+v %+v %+v\n", stream.Address, stream.Port, stream.Service.Name)
	})
	if nil != err {
		log.Printf("scan is error %+v\n", err)
	} else {
		//log.Printf("%+v\n", x)
	}
}
