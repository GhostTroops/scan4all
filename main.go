package main

import (
	"embed"
	"fmt"
	myConst "github.com/hktalent/scan4all/lib"
	"github.com/hktalent/scan4all/pkg"
	naaburunner "github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sync"
	"time"
)

//go:embed config/*
var config embed.FS

func init() {
	pkg.Init2(&config)
	rand.Seed(time.Now().UnixNano())
}

var Wg sync.WaitGroup

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	myConst.Wg = &Wg
	defer func() {
		pkg.Cache1.Close()
		if runtime.GOOS == "windows" || pkg.GetValAsBool("autoRmCache") {
			os.RemoveAll(pkg.GetVal(pkg.CacheName))
		}
		// clear
		// 程序都结束了，没有必要清理内存了
		// fingerprint.ClearData()
	}()
	options := naaburunner.ParseOptions()
	szTip := ""
	if options.Debug && pkg.GetValAsBool("enablDevDebug") {
		// debug 优化时启用///////////////////////
		go func() {
			szTip = "Since you started http://127.0.0.1:6060/debug/pprof/ with -debug, close the program with: control + C"
			fmt.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n\ngo tool pprof -seconds=10 -http=:9999 http://localhost:6060/debug/pprof/heap")
			http.ListenAndServe(":6060", nil)
		}()
		//////////////////////////////////////////*/
	}
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
	if pkg.GetValAsBool("noScan") {
		s1, err := naabuRunner.MergeToFile()
		if nil == err {
			data, err := ioutil.ReadFile(s1)
			if nil == err {
				naaburunner.Naabubuffer.Write(data)
			}
		}
	} else {
		gologger.Info().Msg("Port scan starting....")
		err = naabuRunner.RunEnumeration()
		if err != nil {
			gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
		}
		gologger.Info().Msg("Port scan over,web scan starting")
	}
	err = naabuRunner.Httpxrun()
	if err != nil {
		gologger.Fatal().Msgf("naabuRunner.Httpxrun Could not run httpRunner: %s\n", err)
	}
	log.Printf("wait for all threads to end\n%s", szTip)
	myConst.Wg.Wait()
	myConst.StopAll()
	naabuRunner.Close()
}
