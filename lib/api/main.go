package api

import (
	_ "github.com/hktalent/scan4all/engine"
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// 逐步实现支持 多实例 接口 运行
func StartScan(oOpts *map[string]interface{}) {
	options := util.ParseOptions()
	if options.Update {
		util.UpdateScan4allVersionToLatest(true)
		return
	}
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
	if !options.Debug {
		// disable standard logger (ref: https://github.com/golang/go/issues/19895)
		log.SetFlags(0)
		log.SetOutput(io.Discard)
	}
	// 这里需要解决、优化为非单实例 模式
	util.G_Options = map[string]interface{}{
		"Output": options.Output,
		"JSON":   options.JSON,
		"Debug":  options.Debug,
	}

	util.DoInput(options.Target, options)
	nbopt := naaburunner.ParseOptions()
	if data, err := util.Json.Marshal(options); nil == err {
		util.Json.Unmarshal(data, nbopt)
	}
	naabuRunner, err := naaburunner.NewRunner(nbopt)
	if err != nil {
		gologger.Fatal().Msgf("naaburunner.NewRunner Could not create runner: %s\n", err)
	}
	noScan := util.GetValAsBool("noScan")

	// 直接使用 nmap xml结果文件
	if util.DoNmapWithFile(naaburunner.Naabubuffer.String(), 2) {
		os.Setenv("noScan", "true")
		naabuRunner.Close()
	} else if noScan {
		s1, err := naabuRunner.MergeToFile()
		if nil == err {
			util.DoInput(s1, options)
			data, err := ioutil.ReadFile(s1)
			if nil == err {
				runner.Naabubuffer.Write(data)
			}
		}
		naabuRunner.Close()
	} else {
		//gologger.Info().Msg("Port scan starting....")
		//err = naabuRunner.RunEnumeration()
		//if err != nil {
		//	gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
		//}
		//gologger.Info().Msg("Port scan over,web scan starting")
	}
	err = naabuRunner.Httpxrun(nil, nil)
	if err != nil {
		gologger.Fatal().Msgf("naabuRunner.Httpxrun Could not run httpRunner: %s\n", err)
	}
}
