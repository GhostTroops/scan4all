package main

import (
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pkg/fingerprint"
	httpxrunner "github.com/hktalent/scan4all/pkg/httpx/runner"
	"log"
)

func main() {
	httpxrunner.Naabubuffer.Write([]byte(`http://101.132.254.177:8161
http://101.132.155.38:8161/
http://101.132.34.146:8161
http://47.108.13.164:8080
https://13.251.135.159
http://220.184.147.172:8000
http://223.78.125.18:8086
http://59.46.70.114:8091
http://121.8.249.110:3388
https://116.236.79.37:9100
https://61.240.13.104:444
http://118.195.131.216/
http://117.10.171.174:10010/
http://81.70.143.198:8081
http://1.119.203.138:8181/
http://1.117.5.50/
http://103.235.238.253
http://210.12.80.130:8080
http://47.117.44.62:8087
http://47.96.141.190
https://223.111.9.4
https://115.159.88.218
http://46.26.46.13/
https://182.92.89.1
https://47.104.237.208`))
	if nil == util.Cache1 {
		util.NewKvDbOp()
	}
	httpxoptions := httpxrunner.ParseOptions()
	if "" != fingerprint.FgDictFile {
		httpxoptions.RequestURIs = fingerprint.FgDictFile
	}

	rx, err := httpxrunner.New(httpxoptions)
	if err != nil {
		log.Println(err)
	}
	rx.RunEnumeration()
	rx.Close()
}
