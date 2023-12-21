package pocs_go

import (
	"fmt"
	"github.com/GhostTroops/scan4all/brute"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"github.com/GhostTroops/scan4all/pocs_go/Springboot"
	"github.com/GhostTroops/scan4all/pocs_go/ThinkPHP"
	"github.com/GhostTroops/scan4all/pocs_go/VMware/vCenter"
	"github.com/GhostTroops/scan4all/pocs_go/apache"
	"github.com/GhostTroops/scan4all/pocs_go/confluence"
	"github.com/GhostTroops/scan4all/pocs_go/f5"
	"github.com/GhostTroops/scan4all/pocs_go/fastjson"
	"github.com/GhostTroops/scan4all/pocs_go/gitlab"
	"github.com/GhostTroops/scan4all/pocs_go/jboss"
	"github.com/GhostTroops/scan4all/pocs_go/jenkins"
	"github.com/GhostTroops/scan4all/pocs_go/landray"
	"github.com/GhostTroops/scan4all/pocs_go/log4j"
	"github.com/GhostTroops/scan4all/pocs_go/mcms"
	"github.com/GhostTroops/scan4all/pocs_go/ms"
	"github.com/GhostTroops/scan4all/pocs_go/phpunit"
	"github.com/GhostTroops/scan4all/pocs_go/seeyon"
	"github.com/GhostTroops/scan4all/pocs_go/shiro"
	"github.com/GhostTroops/scan4all/pocs_go/spark"
	"github.com/GhostTroops/scan4all/pocs_go/sunlogin"
	"github.com/GhostTroops/scan4all/pocs_go/tomcat"
	"github.com/GhostTroops/scan4all/pocs_go/tongda"
	"github.com/GhostTroops/scan4all/pocs_go/weblogic"
	"github.com/GhostTroops/scan4all/pocs_go/zabbix"
	"github.com/GhostTroops/scan4all/pocs_go/zentao"
	"log"
	"net/url"
	"strconv"
	"strings"
)

// 需优化：相同都目标，相同都检测只做一次
func POCcheck(wappalyzertechnologies []string, URL string, finalURL string, checklog4j bool) []string {
	if !strings.HasPrefix(finalURL, "http") {
		finalURL = "http://" + finalURL
	}
	u01, err := url.Parse(finalURL)
	if nil != err {
		log.Println(finalURL, err)
		return []string{}
	}
	if util.TestRepeat(wappalyzertechnologies, u01.Host, u01.Host, checklog4j) {
		return []string{}
	}
	var HOST, hostname string
	var technologies []string
	if host, err := url.Parse(strings.TrimSpace(URL)); err == nil {
		HOST = host.Host
		hostname = host.Hostname()
	} else {
		log.Println(URL, " parse error ", err)
		return []string{}
	}
	for tech := range wappalyzertechnologies {
		caseStr := strings.ToLower(wappalyzertechnologies[tech])
		switch caseStr {
		case "ZookeeperUnauthority":
			if apache.ZookeeperUnauthority(finalURL) {
				technologies = append(technologies, fmt.Sprintf("ZookeeperUnauthority %s", finalURL))
			}
		case "httpCheckSmuggling":
			//Smuggling.DoCheckSmuggling(finalURL, "")// close
			break
		case "RouterOS":
			a := ms.CVE_2018_14847(hostname)
			if 0 < len(a) {
				technologies = append(technologies, fmt.Sprintf("CVE-2018-14847 MikroTik RouterOS: %+v", a))
			}
		case "Microsoft Exchange Server":
			s1 := ms.CheckCVE_2021_26855(hostname)
			if "" != s1 {
				technologies = append(technologies, s1)
				a := ms.CheckExchange(&hostname)
				if 0 < len(a) {
					technologies = append(technologies, a...)
				}
			}
			s1 = ms.GetExFQND(hostname)
			if "" != s1 {
				technologies = append(technologies, s1)
			}
		case "msrpc":
			a, err := ms.CheckDCom(hostname)
			if nil != err && 0 < len(a) {
				technologies = append(technologies, fmt.Sprintf("microsoft port 135 Dcom Oxid:%s", hostname))
			}
		case "vmware-vcenter":
			if vCenter.Check_CVE_2021_21985(finalURL) {
				technologies = append(technologies, fmt.Sprintf("CVE-2021-21985 RCE:%s", hostname))
			}
			if s, ok := vCenter.CheckVul001(finalURL); ok {
				technologies = append(technologies, fmt.Sprintf("found vmware RCE,shell:%s", s))
			}
			if s, ok := vCenter.CheckVul002(finalURL); ok {
				technologies = append(technologies, fmt.Sprintf("found vmware RCE,shell:%s", s))
			}
			if s, ok := vCenter.CheckVul003(finalURL); ok {
				technologies = append(technologies, fmt.Sprintf("found vmware RCE,shell:%s", s))
			}
			vCenter.DoCheckCVE_2022_22954(finalURL)
			vCenter.DoCheck(finalURL)
		case "microsoft-ds":
			key, err := ms.SmbGhostScan(hostname)
			if nil == err && key {
				technologies = append(technologies, fmt.Sprintf("exp-microsoft-ds CVE-2020-0796 :%s", hostname))
			}
		case "shiro":
			key := shiro.CVE_2016_4437(finalURL)
			if key != "" {
				technologies = append(technologies, fmt.Sprintf("exp-Shiro|key:%s", key))
			}
		case "apache tomcat":
			if ok, _ := apache.CVE_2020_13935(URL); ok {
				technologies = append(technologies, "exp-Tomcat|CVE-2020-13935")
			}
			username, password := brute.Tomcat_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("brute-Tomcat|%s:%s", username, password))
			}
			if tomcat.CVE_2020_1938(HOST) {
				technologies = append(technologies, "exp-Tomcat|CVE-2020-1938")
			}
			if tomcat.CVE_2017_12615(URL) {
				technologies = append(technologies, "exp-Tomcat|CVE-2017-12615")
			}
		case "basic":
			username, password := brute.Basic_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("brute-basic|%s:%s", username, password))
			}
		case "weblogic":
			username, password := brute.Weblogic_brute(URL)
			if username != "" {
				if username == "login_page" {
					technologies = append(technologies, "Weblogic_login_page")
				} else {
					technologies = append(technologies, fmt.Sprintf("brute-Weblogic|%s:%s", username, password))
				}
			}
			if weblogic.CVE_2014_4210(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2014_4210")
			}
			if weblogic.CVE_2017_3506(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2017_3506")
			}
			if weblogic.CVE_2017_10271(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2017_10271")
			}
			if weblogic.CVE_2018_2894(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2018_2894")
			}
			if weblogic.CVE_2019_2725(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2019_2725")
			}
			if weblogic.CVE_2019_2729(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2019_2729")
			}
			if weblogic.CVE_2020_2883(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2020_2883")
			}
			if weblogic.CVE_2020_14882(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2020_14882")
			}
			if weblogic.CVE_2020_14883(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2020_14883")
			}
			if weblogic.CVE_2021_2109(URL) {
				technologies = append(technologies, "exp-Weblogic|CVE_2021_2109")
			}
		case "jboss application server 7", "jboss", "jboss-as", "jboss-eap", "jboss web", "jboss application server":
			if jboss.CVE_2017_12149(URL) {
				technologies = append(technologies, "exp-jboss|CVE_2017_12149")
			}
			username, password := brute.Jboss_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("brute-jboss|%s:%s", username, password))
			}
		case "json":
			fastjsonRceType := fastjson.Check(URL, finalURL)
			if fastjsonRceType != "" {
				technologies = append(technologies, fmt.Sprintf("exp-FastJson|%s", fastjsonRceType))
			}
		case "jenkins":
			if jenkins.Unauthorized(URL) {
				technologies = append(technologies, "exp-jenkins|Unauthorized script")
			}
			if jenkins.CVE_2018_1000110(URL) {
				technologies = append(technologies, "exp-jenkins|CVE_2018_1000110")
			}
			if jenkins.CVE_2018_1000861(URL) {
				technologies = append(technologies, "exp-jenkins|CVE_2018_1000861")
			}
			if jenkins.CVE_2019_10003000(URL) {
				technologies = append(technologies, "exp-jenkins|CVE_2019_10003000")
			}
		case "thinkphp":
			if ThinkPHP.RCE(URL) {
				technologies = append(technologies, "exp-ThinkPHP")
			}
		case "phpunit":
			if phpunit.CVE_2017_9841(URL) {
				technologies = append(technologies, "exp-phpunit|CVE_2017_9841")
			}
		case "seeyon":
			if seeyon.SeeyonFastjson(URL) {
				technologies = append(technologies, "exp-seeyon|SeeyonFastjson")
			}
			if seeyon.SessionUpload(URL) {
				technologies = append(technologies, "exp-seeyon|SessionUpload")
			}
			if seeyon.CNVD_2019_19299(URL) {
				technologies = append(technologies, "exp-seeyon|CNVD_2019_19299")
			}
			if seeyon.CNVD_2020_62422(URL) {
				technologies = append(technologies, "exp-seeyon|CNVD_2020_62422")
			}
			if seeyon.CNVD_2021_01627(URL) {
				technologies = append(technologies, "exp-seeyon|CNVD_2021_01627")
			}
			if seeyon.CreateMysql(URL) {
				technologies = append(technologies, "exp-seeyon|CreateMysql")
			}
			if seeyon.DownExcelBeanServlet(URL) {
				technologies = append(technologies, "exp-seeyon|DownExcelBeanServlet")
			}
			if seeyon.GetSessionList(URL) {
				technologies = append(technologies, "exp-seeyon|GetSessionList")
			}
			if seeyon.InitDataAssess(URL) {
				technologies = append(technologies, "exp-seeyon|InitDataAssess")
			}
			if seeyon.ManagementStatus(URL) {
				technologies = append(technologies, "exp-seeyon|ManagementStatus")
			}
			if seeyon.BackdoorScan(URL) {
				technologies = append(technologies, "exp-seeyon|Backdoor")
			}
		case "loginpage", "登陆页面", "AdminLoginPage":
			username, password, loginurl := brute.Admin_brute(finalURL)
			if loginurl != "" {
				technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s %s", username, password, loginurl))
			}
		case "sunlogin":
			if sunlogin.SunloginRCE(URL) {
				technologies = append(technologies, "exp-Sunlogin|RCE")
			}
		case "zabbixsaml":
			if zabbix.CVE_2022_23131(URL) {
				technologies = append(technologies, "exp-ZabbixSAML|bypass-login")
			}
		case "spring", "spring env", "spring-boot", "spring-framework", "spring-boot-admin":
			if Springboot.CVE_2022_22965(finalURL) {
				technologies = append(technologies, "exp-Spring4Shell|CVE_2022_22965")
			}
		case "springgateway":
			if Springboot.CVE_2022_22947(URL) {
				technologies = append(technologies, "exp-SpringGateway|CVE_2022_22947")
			}
		case "gitlab":
			if gitlab.CVE_2021_22205(URL) {
				technologies = append(technologies, "exp-gitlab|CVE_2021_22205")
			}
		case "confluence":
			if confluence.CVE_2021_26084(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2021_26084")
			}
			if confluence.CVE_2021_26085(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2021_26085")
			}
			if confluence.CVE_2022_26134(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2022_26134")
			}
			if confluence.CVE_2022_26138(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2022_26138")
			}
		case "f5 big ip":
			if f5.CVE_2020_5902(URL) {
				technologies = append(technologies, "exp-f5-Big-IP|CVE_2020_5902")
			}
			if f5.CVE_2021_22986(URL) {
				technologies = append(technologies, "exp-f5-Big-IP|CVE_2021_22986")
			}
			if f5.CVE_2022_1388(URL) {
				technologies = append(technologies, "exp-f5-Big-IP|CVE_2022_1388")
			}
		case "禅道":
			if zentao.CNVD_2022_42853(URL) {
				technologies = append(technologies, "GoPOC_禅道|CNVD_2022_42853")
			}
		case "spark-jobs":
			if spark.CVE_2022_33891(URL) {
				technologies = append(technologies, "GoPOC_spark|CVE_2022_33891")
			}
		case "蓝凌 OA":
			if landray.Landray_RCE(URL) {
				technologies = append(technologies, "GoPOC_Landray|Landray_RCE")
			}
		case "通达OA":
			if tongda.Get_user_session(URL) {
				technologies = append(technologies, "GoPOC_Tongda|Tongda_get_user_session")
			}
			if tongda.File_delete(URL) {
				technologies = append(technologies, "GoPOC_Tongda|Tongda_File_delete")
			}
			if tongda.File_upload(URL) {
				technologies = append(technologies, "GoPOC_Tongda|Tongda_File_upload")
			}
		case "铭飞MCms":
			if mcms.Front_Sql_inject(URL) {
				technologies = append(technologies, "GoPOC_Mcms|Mcms_Front_Sql_inject")
			}
		}

		if checklog4j {
			if log4j.Check(URL, finalURL) {
				technologies = append(technologies, "exp-log4j|JNDI RCE")
			}
		}
	}
	// 发送结果
	if 0 < len(technologies) {
		util.SendEngineLog4Url(finalURL, Const.ScanType_GoPoc, &map[string]interface{}{"Urls": []string{URL, finalURL}, "technologies": technologies}, util.Scan4all)
	}
	return technologies
}

func init() {
	util.RegInitFunc(func() {
		// 基于工厂方法构建
		util.EngineFuncFactory(Const.ScanType_GoPoc, func(evt *models.EventData, args ...interface{}) {
			_, fileFuzzTechnologies := brute.FileFuzz(evt.Task.ScanWeb, 200, 100, "")
			resp1, reqbody, _, err := util.GetResponse("", "", evt.Task.ScanWeb, "GET", "", false, nil)
			if nil == err && nil != resp1 {
				a, _ := fingerprint.FingerScan(*resp1.Header, []byte(reqbody), "", evt.Task.ScanWeb, strconv.Itoa(resp1.StatusCode))
				if 0 < len(a) {
					fileFuzzTechnologies = append(fileFuzzTechnologies, a...)
				}
			}
			util.SendEvent(evt, Const.ScanType_Nmap, Const.ScanType_Masscan)
			// 一旦开启nmap等，其他的结果，将在其他流程中反馈，并做防止重复的处理
			pocs := POCcheck(fileFuzzTechnologies, evt.Task.ScanWeb, evt.Task.ScanWeb, true)
			util.SendEngineLog(evt, Const.ScanType_GoPoc, pocs)
		})
	})
}
