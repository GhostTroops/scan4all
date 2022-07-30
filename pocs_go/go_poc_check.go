package pocs_go

import (
	"fmt"
	"github.com/hktalent/scan4all/brute"
	"github.com/hktalent/scan4all/lib/Smuggling"
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pocs_go/Springboot"
	"github.com/hktalent/scan4all/pocs_go/ThinkPHP"
	"github.com/hktalent/scan4all/pocs_go/apache"
	"github.com/hktalent/scan4all/pocs_go/confluence"
	"github.com/hktalent/scan4all/pocs_go/f5"
	"github.com/hktalent/scan4all/pocs_go/fastjson"
	"github.com/hktalent/scan4all/pocs_go/gitlab"
	"github.com/hktalent/scan4all/pocs_go/jboss"
	"github.com/hktalent/scan4all/pocs_go/jenkins"
	"github.com/hktalent/scan4all/pocs_go/log4j"
	"github.com/hktalent/scan4all/pocs_go/ms"
	"github.com/hktalent/scan4all/pocs_go/phpunit"
	"github.com/hktalent/scan4all/pocs_go/seeyon"
	"github.com/hktalent/scan4all/pocs_go/shiro"
	"github.com/hktalent/scan4all/pocs_go/sunlogin"
	"github.com/hktalent/scan4all/pocs_go/tomcat"
	"github.com/hktalent/scan4all/pocs_go/weblogic"
	"github.com/hktalent/scan4all/pocs_go/zabbix"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

// 需优化：相同都目标，相同都检测只做一次
func POCcheck(wappalyzertechnologies []string, URL string, finalURL string, checklog4j bool) []string {
	if nil != util.Wg {
		defer util.Wg.Done()
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
		case "httpCheckSmuggling":
			Smuggling.DoCheckSmuggling(finalURL, "")
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
				technologies = append(technologies, fmt.Sprintf("microsoft port 135 Dcom :%s", hostname))
			}
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
		case "loginpage":
			username, password, loginurl := brute.Admin_brute(finalURL)
			if loginurl != "" {
				technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s", username, password))
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
		}
		if checklog4j {
			if log4j.Check(URL, finalURL) {
				technologies = append(technologies, "exp-log4j|JNDI RCE")
			}
		}
	}
	// 发送结果
	if 0 < len(technologies) {
		util.SendAnyData(&map[string]interface{}{"Urls": []string{URL, finalURL}, "technologies": technologies}, util.Scan4all)
	}
	return technologies
}

func init() {
	util.RegInitFunc(func() {
		// 异步启动一个线程处理检测，避免
		util.Wg.Add(1)
		go func() {
			defer util.Wg.Done()
			nMax := 120 // 等xxx秒都没有消息进入就退出
			nCnt := 0
			for {
				select {
				case <-util.Ctx_global.Done():
					return
				case x1, ok := <-util.PocCheck_pipe:
					if nil == x1 || !ok {
						log.Println("go_poc_checkout is over")
						return
					}
					nCnt = 0
					log.Printf("<-lib.PocCheck_pipe: %+v  %s", *x1.Wappalyzertechnologies, x1.URL)
					util.Wg.Add(1)
					go POCcheck(*x1.Wappalyzertechnologies, x1.URL, x1.FinalURL, x1.Checklog4j)
				default:
					if os.Getenv("NoPOC") == "true" {
						close(util.PocCheck_pipe)
						return
					}
					var f01 float32 = float32(nCnt) / float32(nMax) * float32(100)
					fmt.Printf(" Asynchronous go PoCs detection task %%%0.2f ....\r", f01)
					<-time.After(time.Duration(1) * time.Second)
					nCnt += 1
					if nMax <= nCnt {
						close(util.PocCheck_pipe)
						return
					}
				}
			}
		}()
	})
}
