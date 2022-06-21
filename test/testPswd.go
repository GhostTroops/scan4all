package main

import (
	"github.com/hktalent/scan4all/pkg/hydra"
)

func main() {
	hydra.Start("18.163.182.231", 22, "ssh")
}
