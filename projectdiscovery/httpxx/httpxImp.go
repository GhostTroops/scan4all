package httpxx

import (
	"bytes"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pkg/fingerprint"
	httpxrunner "github.com/hktalent/ProScan4all/pkg/httpx/runner"
	"github.com/hktalent/ProScan4all/projectdiscovery/nuclei_Yaml"
	runner2 "github.com/hktalent/ProScan4all/projectdiscovery/nuclei_Yaml/nclruner/runner"
	"github.com/hktalent/ProScan4all/webScan"
	runner3 "github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func Httpxrun(buf *bytes.Buffer, options *runner3.Options) error {
	httpxrunner.Naabubuffer = *buf
	var nucleiDone = make(chan bool, 1)
	Cookie := util.GetVal("Cookie")
	if "" != Cookie {
		Cookie = "Cookie: " + Cookie + ";rememberMe=123" // add
	}
	//log.Printf("%+v", httpxrunner.Naabubuffer.String())
	// 集成nuclei
	//log.Println("httpxrunner.Naabubuffer = ", httpxrunner.Naabubuffer.String())
	//Naabubuffer1 := bytes.Buffer{}
	//Naabubuffer1.Write(httpxrunner.Naabubuffer.Bytes())
	var xx1 = make(chan *runner2.Runner, 1)
	httpxoptions := httpxrunner.ParseOptions()

	opts := map[string]interface{}{}
	if "" != Cookie {
		if nil == httpxoptions.CustomHeaders {
			httpxoptions.CustomHeaders = []string{Cookie}
		} else {
			httpxoptions.CustomHeaders.Set(Cookie)
		}
		var a []string
		a = append(a, httpxoptions.CustomHeaders...)
		opts["CustomHeaders"] = a
		util.CustomHeaders = append(util.CustomHeaders, a...)
	}
	//var axx1 []*runner2.Runner

	util.DoSyncFunc(func() {
		if util.GetValAsBool("enableWebScan") {
			util.DoSyncFunc(func() {
				webScan.CheckUrls(&httpxrunner.Naabubuffer)
			})
		}
		if util.GetValAsBool("enableMultNuclei") {
			go nuclei_Yaml.RunNucleiP(&httpxrunner.Naabubuffer, nucleiDone, &opts, xx1)
			<-nucleiDone
		} else if util.GetValAsBool("enableNuclei") {
			go nuclei_Yaml.RunNuclei(&httpxrunner.Naabubuffer, nucleiDone, &opts, xx1)
			<-nucleiDone
		}
	})
	// 指纹去重复 请求路径
	if "" != fingerprint.FgDictFile {
		httpxoptions.RequestURIs = fingerprint.FgDictFile
		//fmt.Println("httpxoptions.RequestURIs: ", httpxoptions.RequestURIs)
	}

	httpxoptions.Output = options.Output
	httpxoptions.CSVOutput = options.CSV
	httpxoptions.JSONOutput = options.JSON
	httpxoptions.HTTPProxy = options.Proxy
	httpxoptions.Threads = options.Threads
	httpxoptions.Verbose = options.Verbose
	httpxoptions.NoColor = options.NoColor
	httpxoptions.Silent = options.Silent
	httpxoptions.Version = options.Version
	httpxoptions.RateLimit = options.Rate

	httpxoptions.NoPOC = util.GetValAsBool("NoPOC")
	httpxoptions.CeyeApi = util.GetVal("CeyeApi")
	httpxoptions.CeyeDomain = util.GetVal("CeyeDomain")
	util.CeyeApi = util.GetVal("CeyeApi")
	util.CeyeDomain = util.GetVal("CeyeDomain")
	util.HttpProxy = options.Proxy
	util.Fuzzthreads = options.Threads

	if httpxoptions.RateLimit == 0 {
		httpxoptions.RateLimit = 1
	}

	//httpxoptions.NoColor = r.options.NoColor
	//httpxoptions.Silent = r.options.Silent
	//httpxoptions.Output = r.options.Output
	//httpxoptions.HTTPProxy = r.options.Proxy
	//httpxoptions.NoPOC = r.options.NoPOC
	//jndi.JndiAddress = r.options.LocalJndiAddress
	//brute.SkipAdminBrute = r.options.SkipAdminBrute
	//pkg.CeyeApi = r.options.CeyeApi
	//pkg.CeyeDomain = r.options.CeyeDomain
	//pkg.HttpProxy = r.options.Proxy
	//pkg.NoColor = r.options.NoColor
	//pkg.Output = r.options.Output
	//httpxoptions.Naabuinput = Naabuipports
	//if jndi.JndiAddress != "" {
	//	go jndi.JndiServer()
	//}

	// json 控制参数
	httpxoptions = util.ParseOption[httpxrunner.Options]("httpx", httpxoptions)
	rx, err := httpxrunner.New(httpxoptions)
	if err != nil {
		return err
	}
	rx.RunEnumeration()
	rx.Close()
	// wait nuclei
	return nil
}
