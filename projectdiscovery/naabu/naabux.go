package naabu

import (
	"bytes"
	"fmt"
	"github.com/hktalent/ProScan4all/lib/util"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"os"
)

// https://github.com/projectdiscovery/naabu
func DoNaabu(buf *bytes.Buffer) *runner.Options {
	// options := runner.ParseOptions("-host", strings.Join(target, ","), "-v")
	options := runner.ParseOptions(os.Args[1:]...)

	options.OnResult = func(r1 *result.HostResult) {
		// port
		if nil != r1 {

			for _, k := range r1.Ports {
				buf.WriteString(fmt.Sprintf("http://%s:%d\nhttps://%s:%d\n", r1.Host, k, r1.Host, k))
			}

		} else {
			buf.WriteString(fmt.Sprintf("http://%s\nhttps://%s\n", r1.Host, r1.Host))
		}
		//fmt.Printf("test %+v", out)
	}
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	util.RegCbk("exit", func() {
		naabuRunner.ShowScanResultOnExit()
		gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
		if options.ResumeCfg.ShouldSaveResume() {
			gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFilePath())
			err := options.ResumeCfg.SaveResumeConfig()
			if err != nil {
				gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}
		}
		naabuRunner.Close()
	})
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	// on successful execution remove the resume file in case it exists
	options.ResumeCfg.CleanupResumeConfig()
	return options
}
