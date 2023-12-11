package api

import (
	"encoding/json"
	_ "github.com/GhostTroops/scan4all/engine"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/hydra"
	naaburunner "github.com/GhostTroops/scan4all/pkg/naabu/v2/pkg/runner"
	util1 "github.com/hktalent/go-utils"
	"github.com/projectdiscovery/gologger"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
)

// 逐步实现支持 多实例 接口 运行
func StartScan(oOpts *map[string]interface{}) {
	util.DoSyncFunc(func() {
		//buf1 := bytes.Buffer{}
		//opt001 := naabu.DoNaabu(&buf1)

		options := naaburunner.ParseOptions()
		if options.Update {
			util1.UpdateScan4allVersionToLatest(true, "hktalent", "scan4all", "")
			return
		}
		//if options.Ports != "" {
		//	os.Setenv("priorityNmap", "false")
		//}
		// 压入外部参数
		if nil != oOpts {
			// 指定覆盖
			data, err := json.Marshal(oOpts)
			if nil == err && 0 < len(data) {
				err := json.Unmarshal(data, options)
				if nil != err {
					log.Println("oOpts err ", err)
				}
			}
		}
		if false == options.Debug && false == options.Verbose {
			// disable standard logger (ref: https://github.com/golang/go/issues/19895)
			log.SetFlags(0)
			log.SetOutput(io.Discard)
		}
		util.Output = options.Output
		// 这里需要解决、优化为非单实例 模式
		util.G_Options = map[string]interface{}{
			"Output":            options.Output,
			"JSON":              options.JSON,
			"Stream":            options.Stream,
			"Verbose":           options.Verbose,
			"Silent":            options.Silent,
			"Debug":             options.Debug,
			"EnableProgressBar": options.EnableProgressBar, // 开启进度条
		}

		if runtime.GOOS == "windows" {
			options.NoColor = true
		}

		naabuRunner, err := naaburunner.NewRunner(options)
		if err != nil {
			gologger.Fatal().Msgf("naaburunner.NewRunner Could not create runner: %s\n", err)
		}
		noScan := util.GetValAsBool("noScan")

		// 直接使用 nmap xml结果文件
		if hydra.DoNmapWithFile(options.HostsFile, &naaburunner.Naabubuffer) {
			os.Setenv("noScan", "true")
			naabuRunner.Close()
		} else if noScan {
			s1, err := naabuRunner.MergeToFile()
			if nil == err {
				data, err := ioutil.ReadFile(s1)
				if nil == err {
					naaburunner.Naabubuffer.Write(data)
				}
			}
			naabuRunner.Close()
		} else {
			gologger.Info().Msg("Port scan starting....")
			err = naabuRunner.RunEnumeration()
			if err != nil {
				gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
			}
			gologger.Info().Msg("Port scan over,web scan starting")
		}
		err = naabuRunner.Httpxrun(nil, nil)
		if err != nil {
			gologger.Fatal().Msgf("naabuRunner.Httpxrun Could not run httpRunner: %s\n", err)
		}
	})
}
