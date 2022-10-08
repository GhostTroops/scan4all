package main

import (
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pkg/fingerprint"
	httpxrunner "github.com/hktalent/ProScan4all/pkg/httpx/runner"
	"log"
)

func main() {
	httpxrunner.Naabubuffer.Write([]byte(``))
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
