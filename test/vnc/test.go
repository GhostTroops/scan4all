package main

import (
	"github.com/GhostTroops/scan4all/pkg/hydra/vnc"
	"log"
	"net"
)

func main() {
	nc, err := net.Dial("tcp", "192.168.0.100:5900")
	if err != nil {
		log.Println(err)
		return
	}

	cc1, err := vnc.Client(nc, &vnc.ClientConfig{Auth: []vnc.ClientAuth{&vnc.PasswordAuth{Password: "testnmanp"}}})
	if err != nil {
		log.Println(err)
	} else {
		cc1.Close()
	}
}
