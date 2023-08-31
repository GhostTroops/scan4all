package main

import (
	"embed"
	_ "github.com/hktalent/scan4all/engine"
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pocs_go/log4j"
)

//go:embed config/*
var config1 embed.FS

// log4j 系列
//
//	1、log4j盲打全套，包含struts2 根目录、二级目录
//	2、VCenter
//	3、CheckTemenosT24
//	4、Solr 上传jsp不会被解析
//	5、struts2
func main() {
	util.DoInit(&config1)
	szUrl := "http://127.0.0.1:8080/"
	if log4j.Check(szUrl, szUrl) {

	}
	//if log4j.VCenter(szUrl) {
	//
	//}
	//log4j.CheckTemenosT24(szUrl)
	//log4j.Solr(szUrl)
	util.Wg.Wait()
	util.CloseAll()
}
