package brute

import (
	_ "embed"
	"github.com/GhostTroops/scan4all/lib/util"
	"regexp"
	"strings"
)

//go:embed dicts/cprt.txt
var supplyChainPrefix string

//go:embed dicts/softc.txt
var supplyChainEndstr string

func init() {
	util.RegInitFunc(func() {
		p1 := "((" + strings.Join(strings.Split(strings.TrimSpace(supplyChainPrefix), "\n"), ")|(") + "))\\s*[:：]\\s*"
		p2 := "((" + strings.Join(strings.Split(strings.TrimSpace(supplyChainEndstr), "\n"), ")|(") + "))"
		util.SupplyChainReg = regexp.MustCompile(p1 + p2)
	})
}
