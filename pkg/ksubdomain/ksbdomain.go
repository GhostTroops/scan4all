package ksubdomain

import (
	"github.com/boy-hack/ksubdomain/core/conf"
	"github.com/boy-hack/ksubdomain/core/gologger"
	cli "github.com/urfave/cli/v2"
	"os"
)

// cat $HOME/MyWork/scan4all/pkg/ksubdomain/*.go|grep "github.com/boy-hack/ksubdomain"|sed 's/"//g'|sort -u|uniq|xargs -I % go get %
func DoSubfinder(a []string, out chan string, done chan bool) {
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

	err := app.Run(os.Args)
	if err != nil {
		gologger.Fatalf(err.Error())
	}
}
