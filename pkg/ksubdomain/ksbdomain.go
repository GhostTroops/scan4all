package ksubdomain

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/boy-hack/ksubdomain/core/conf"
	"github.com/boy-hack/ksubdomain/core/gologger"
	cli "github.com/urfave/cli/v2"
	"os"
	"regexp"
)

// cat $HOME/MyWork/scan4all/pkg/ksubdomain/*.go|grep "github.com/boy-hack/ksubdomain"|sed 's/"//g'|sort -u|uniq|xargs -I % go get %
func DoSubfinder(a []string, out chan string, done chan bool) {
	if util.GetValAsBool("EnableKsubdomain") {
		s1 := util.GetVal("KsubdomainRegxp")
		if "" != s1 {
			r1, err := regexp.Compile(s1)
			if nil == err {
				a1 := []string{}
				for _, x := range a {
					x3 := r1.FindAllString(x, -1)
					if 0 < len(x3) {
						a1 = append(a1, x3[0])
					}
				}
				a = a1
			}
			app := &cli.App{
				Name:    conf.AppName,
				Version: conf.Version,
				Usage:   conf.Description,
				Commands: []*cli.Command{
					enumCommand,
					verifyCommand,
					testCommand,
				},
			}

			err = app.Run(os.Args)
			if err != nil {
				gologger.Fatalf(err.Error())
			}

		}
	}
}
