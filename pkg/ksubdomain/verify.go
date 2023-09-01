package ksubdomain

import (
	"bufio"
	"context"
	"github.com/boy-hack/ksubdomain/core"
	"github.com/boy-hack/ksubdomain/core/gologger"
	"github.com/boy-hack/ksubdomain/core/options"
	"github.com/boy-hack/ksubdomain/runner"
	"github.com/boy-hack/ksubdomain/runner/outputter"
	"github.com/boy-hack/ksubdomain/runner/outputter/output"
	"github.com/boy-hack/ksubdomain/runner/processbar"
	"github.com/urfave/cli/v2"
	"os"
)

var commonFlags = []cli.Flag{
	&cli.StringFlag{
		Name:     "domain",
		Aliases:  []string{"d"},
		Usage:    "域名",
		Required: false,
		Value:    "",
	},
	&cli.StringFlag{
		Name:     "band",
		Aliases:  []string{"b"},
		Usage:    "宽带的下行速度，可以5M,5K,5G",
		Required: false,
		Value:    "2m",
	},
	&cli.StringFlag{
		Name:     "resolvers",
		Aliases:  []string{"r"},
		Usage:    "dns服务器文件路径，一行一个dns地址，默认会使用内置dns",
		Required: false,
		Value:    "",
	},
	&cli.StringFlag{
		Name:     "output",
		Aliases:  []string{"o"},
		Usage:    "输出文件名",
		Required: false,
		Value:    "",
	},
	&cli.BoolFlag{
		Name:  "silent",
		Usage: "使用后屏幕将仅输出域名",
		Value: false,
	},
	&cli.IntFlag{
		Name:  "retry",
		Usage: "重试次数,当为-1时将一直重试",
		Value: 3,
	},
	&cli.IntFlag{
		Name:  "timeout",
		Usage: "超时时间",
		Value: 6,
	},
	&cli.BoolFlag{
		Name:  "stdin",
		Usage: "接受stdin输入",
		Value: false,
	},
	&cli.BoolFlag{
		Name:    "only-domain",
		Aliases: []string{"od"},
		Usage:   "只打印域名，不显示ip",
		Value:   false,
	},
	&cli.BoolFlag{
		Name:    "not-print",
		Aliases: []string{"np"},
		Usage:   "不打印域名结果",
		Value:   false,
	},
	&cli.StringFlag{
		Name:  "dns-type",
		Usage: "dns类型 可以是a,aaaa,ns,cname,txt",
		Value: "a",
	},
}

var verifyCommand = &cli.Command{
	Name:    runner.VerifyType,
	Aliases: []string{"v"},
	Usage:   "验证模式",
	Flags: append([]cli.Flag{
		&cli.StringFlag{
			Name:     "filename",
			Aliases:  []string{"f"},
			Usage:    "验证域名文件路径",
			Required: false,
			Value:    "",
		},
	}, commonFlags...),
	Action: func(c *cli.Context) error {
		if c.NumFlags() == 0 {
			cli.ShowCommandHelpAndExit(c, "verify", 0)
		}
		var domains []string
		var writer []outputter.Output
		var processBar processbar.ProcessBar = &processbar.ScreenProcess{}
		if c.String("domain") != "" {
			domains = append(domains, c.String("domain"))
		}
		if c.Bool("stdin") {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				domains = append(domains, scanner.Text())
			}
		}
		var total int = 0
		total += len(domains)
		render := make(chan string)
		if c.String("filename") != "" {
			t, err := core.LinesReaderInFile(c.String("filename"))
			if err != nil {
				gologger.Fatalf("打开文件:%s 出现错误:%s", c.String("filename"), err.Error())
			}
			total += t
		}
		go func() {
			for _, line := range domains {
				render <- line
			}
			if c.String("filename") != "" {
				f2, err := os.Open(c.String("filename"))
				if err != nil {
					gologger.Fatalf("打开文件:%s 出现错误:%s", c.String("filename"), err.Error())
				}
				defer f2.Close()
				iofile := bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				for iofile.Scan() {
					render <- iofile.Text()
				}
			}
			close(render)
		}()

		onlyDomain := c.Bool("only-domain")
		if c.String("output") != "" {
			fileWriter, err := output.NewFileOutput(c.String("output"), onlyDomain)
			if err != nil {
				gologger.Fatalf(err.Error())
			}
			writer = append(writer, fileWriter)
		}
		if c.Bool("not-print") {
			processBar = nil
		}
		screenWriter, err := output.NewScreenOutput(onlyDomain)
		if err != nil {
			gologger.Fatalf(err.Error())
		}
		writer = append(writer, screenWriter)

		opt := &options.Options{
			Rate:        options.Band2Rate(c.String("band")),
			Domain:      render,
			DomainTotal: total,
			Resolvers:   options.GetResolvers(c.String("resolvers")),
			Silent:      c.Bool("silent"),
			TimeOut:     c.Int("timeout"),
			Retry:       c.Int("retry"),
			Method:      runner.VerifyType,
			DnsType:     c.String("dns-type"),
			Writer:      writer,
			ProcessBar:  processBar,
		}
		opt.Check()
		opt.EtherInfo = options.GetDeviceConfig()
		ctx := context.Background()
		r, err := runner.New(opt)
		if err != nil {
			gologger.Fatalf("%s\n", err.Error())
			return nil
		}
		r.RunEnumeration(ctx)
		r.Close()
		return nil
	},
}
