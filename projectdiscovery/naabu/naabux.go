package naabu

import (
	"bytes"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// https://github.com/projectdiscovery/naabu
func DoNaabu(buf *bytes.Buffer) *runner.Options {
	// options := runner.ParseOptions("-host", strings.Join(target, ","), "-v")
	//options := runner.ParseOptions(os.Args[1:]...)
	//naabuRunner, err := runner.NewRunner(options)
	//if err != nil {
	//	gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	//}
	//naabuRunner.OutCbk = func(out ...interface{}) {
	//	// port
	//	if nil != out[2] {
	//		if a, ok := out[2].([]string); ok {
	//			for _, k := range a {
	//				buf.WriteString(fmt.Sprintf("http://%s:%s\nhttps://%s:%s\n", out[0], k, out[0], k))
	//			}
	//		}
	//	} else {
	//		buf.WriteString(fmt.Sprintf("http://%s\nhttps://%s\n", out[0], out[0]))
	//	}
	//	//fmt.Printf("test %+v", out)
	//}
	//
	//err = naabuRunner.RunEnumeration()
	//if err != nil {
	//	gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	//}
	//// on successful execution remove the resume file in case it exists
	//options.ResumeCfg.CleanupResumeConfig()
	//return options
	return nil
}
