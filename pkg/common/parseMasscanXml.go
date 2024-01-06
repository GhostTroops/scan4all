package common

import (
	"fmt"
	util1 "github.com/hktalent/go-utils"
	"regexp"
)

var r1IpPort = regexp.MustCompile(`addr="([^"]+)".*portid="([^"]+)"`)

func ParseMasscanXmlCbk(cbk func(string, string), a ...string) {
	var out = util1.ReadFile4Line(a...)
	for s := range out {
		if a1 := r1IpPort.FindStringSubmatch(*s); 3 <= len(a1) {
			cbk(a1[1], a1[2])
		}
	}
}

func ParseMasscanXml(a ...string) {
	ParseMasscanXmlCbk(func(s string, s2 string) {
		fmt.Printf("%s:%s\n", s, s2)
	}, a...)
}
