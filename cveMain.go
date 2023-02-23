package main

import (
	"embed"
	_ "github.com/hktalent/ProScan4all/engine"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pocs_go"
	"github.com/hktalent/ProScan4all/pocs_go/Springboot"
	"github.com/hktalent/ProScan4all/pocs_go/ThinkPHP"
	"github.com/hktalent/ProScan4all/pocs_go/VMware/vCenter"
	"github.com/hktalent/ProScan4all/pocs_go/apache"
	"github.com/hktalent/ProScan4all/pocs_go/confluence"
	"github.com/hktalent/ProScan4all/pocs_go/f5"
	"github.com/hktalent/ProScan4all/pocs_go/fastjson"
	"github.com/hktalent/ProScan4all/pocs_go/gitlab"
	"github.com/hktalent/ProScan4all/pocs_go/jboss"
	"github.com/hktalent/ProScan4all/pocs_go/jenkins"
	"github.com/hktalent/ProScan4all/pocs_go/landray"
	"github.com/hktalent/ProScan4all/pocs_go/mcms"
	"github.com/hktalent/ProScan4all/pocs_go/ms"
	"github.com/hktalent/ProScan4all/pocs_go/phpunit"
	"github.com/hktalent/ProScan4all/pocs_go/ruby"
	"github.com/hktalent/ProScan4all/pocs_go/seeyon"
	"github.com/hktalent/ProScan4all/pocs_go/spark"
	"github.com/hktalent/ProScan4all/pocs_go/sunlogin"
	"github.com/hktalent/ProScan4all/pocs_go/tomcat"
	"github.com/hktalent/ProScan4all/pocs_go/tongda"
	"github.com/hktalent/ProScan4all/pocs_go/weblogic"
	"github.com/hktalent/ProScan4all/pocs_go/zabbix"
	"github.com/hktalent/ProScan4all/pocs_go/zentao"
	"log"
	"os"
)

//go:embed config/*
var Config embed.FS

// 多个web cve 检测
func main1() {
	util.DoInit(&Config)
	for _, cbk := range []func(string) bool{
		ruby.DoCheck,
		apache.CVE_2020_13935Noe,
		confluence.CVE_2021_26084,
		confluence.CVE_2022_26134,
		confluence.CVE_2022_26138,
		confluence.CVE_2021_26085,
		f5.CVE_2020_5902,
		f5.CVE_2021_22986,
		f5.CVE_2022_1388,
		fastjson.CheckFj,
		gitlab.CVE_2021_22205,
		jboss.CVE_2017_12149,
		jenkins.CVE_2018_1000110,
		jenkins.CVE_2018_1000861,
		jenkins.CVE_2019_10003000,
		jenkins.Unauthorized,
		jenkins.DoCheck,
		landray.Landray_RCE,
		mcms.Front_Sql_inject,
		ms.SmbGhostScanNe,
		phpunit.CVE_2017_9841,
		seeyon.BackdoorScan,
		seeyon.CNVD_2019_19299,
		seeyon.CNVD_2020_62422,
		seeyon.CNVD_2021_01627,
		seeyon.CreateMysql,
		seeyon.DownExcelBeanServlet,
		seeyon.GetSessionList,
		seeyon.InitDataAssess,
		seeyon.ManagementStatus,
		seeyon.SeeyonFastjson,
		spark.CVE_2022_33891,
		Springboot.CVE_2022_22947,
		Springboot.CVE_2022_22965,
		sunlogin.SunloginRCE,
		ThinkPHP.RCE,
		tomcat.CVE_2017_12615,
		tomcat.CVE_2020_1938,
		pocs_go.DoCheck,
		pocs_go.DoCheckCVE202138647,
		zabbix.CVE_2022_23131,
		zentao.CNVD_2022_42853,
		tongda.File_delete,
		tongda.Get_user_session,
		tongda.File_upload,
		vCenter.Check_CVE_2021_21985,
		weblogic.CVE_2020_14883,
		weblogic.CVE_2020_14882,
		weblogic.CVE_2020_2883,
		weblogic.CVE_2019_2729,
		weblogic.CVE_2019_2725,
		weblogic.CVE_2018_2894,
		weblogic.CVE_2017_10271,
		weblogic.CVE_2017_3506,
		weblogic.CVE_2014_4210,
		weblogic.CVE_2021_2109,
	} {
		cbk1 := cbk
		util.DefaultPool.Submit(func() {
			defer func() {
				if o := recover(); nil != o {
					log.Println(o)
				}
			}()
			cbk1(os.Args[1])
		})
	}
	util.Wg.Wait()
	util.CloseAll()
}
