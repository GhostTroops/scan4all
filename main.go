package main

import (
	"embed"
	"github.com/hktalent/scan4all/pkg"
	"github.com/hktalent/scan4all/pkg/hydra"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"
)

//go:embed config/*
var config embed.FS

func doFile(config *embed.FS, s fs.DirEntry, szPath string) {
	os.MkdirAll(szPath, os.ModePerm)
	szPath = szPath + "/" + s.Name()
	if pkg.FileExists(szPath) {
		return
	}
	if data, err := config.ReadFile(szPath); nil == err {
		if err := ioutil.WriteFile(szPath, data, os.ModePerm); nil == err {
			//log.Println("write ok: ", szPath)
		}
	}
}
func doDir(config *embed.FS, s fs.DirEntry, szPath string) {
	szPath = szPath + "/" + s.Name()
	if x1, err := config.ReadDir(szPath); nil == err {
		for _, x2 := range x1 {
			if x2.IsDir() {
				doDir(config, x2, szPath)
			} else {
				doFile(config, x2, szPath)
			}
		}
	} else {
		log.Println("doDir:", err)
	}
}
func Init(config *embed.FS) {
	szPath := "config"
	log.Println("wait for init config files ... ")
	if x1, err := config.ReadDir(szPath); nil == err {
		for _, x2 := range x1 {
			if x2.IsDir() {
				doDir(config, x2, szPath)
			} else {
				doFile(config, x2, szPath)
			}
		}
	} else {
		log.Println("Init:", err)
	}
	pkg.Init()
	log.Println("init config files is over .")
}
func init() {
	Init(&config)
}
func main() {

	defer func() {
		pkg.Cache1.Close()
		//if "true" == pkg.GetVal("autoRmCache") {
		//	os.RemoveAll(pkg.GetVal(pkg.CacheName))
		//}
	}()
	options := naaburunner.ParseOptions()
	if false == options.Debug && false == options.Verbose {
		// disable standard logger (ref: https://github.com/golang/go/issues/19895)
		log.SetFlags(0)
		log.SetOutput(io.Discard)
	}
	pkg.G_Options = options
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}
	naabuRunner, err := naaburunner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("naaburunner.NewRunner Could not create runner: %s\n", err)
	}
	gologger.Info().Msg("Port scan starting....")
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	gologger.Info().Msg("Port scan over,web scan starting")
	hvNmap := pkg.CheckHvNmap()
	var wg sync.WaitGroup
	if hvNmap {
		// 弱密码检测
		wg.Add(1)
		go hydra.DoNmapRst(&wg)
	}
	err = naabuRunner.Httpxrun()
	if err != nil {
		gologger.Fatal().Msgf("naabuRunner.Httpxrun Could not run httpRunner: %s\n", err)
	}
	if hvNmap {
		wg.Wait()
	}
}
