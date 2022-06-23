package pocs_go

import (
	"fmt"
	"github.com/hktalent/scan4all/brute"
	"github.com/hktalent/scan4all/pocs_go/Springboot"
	"github.com/hktalent/scan4all/pocs_go/ThinkPHP"
	"github.com/hktalent/scan4all/pocs_go/confluence"
	"github.com/hktalent/scan4all/pocs_go/f5"
	"github.com/hktalent/scan4all/pocs_go/fastjson"
	"github.com/hktalent/scan4all/pocs_go/gitlab"
	"github.com/hktalent/scan4all/pocs_go/jboss"
	"github.com/hktalent/scan4all/pocs_go/jenkins"
	"github.com/hktalent/scan4all/pocs_go/log4j"
	"github.com/hktalent/scan4all/pocs_go/phpunit"
	"github.com/hktalent/scan4all/pocs_go/seeyon"
	"github.com/hktalent/scan4all/pocs_go/shiro"
	"github.com/hktalent/scan4all/pocs_go/sunlogin"
	"github.com/hktalent/scan4all/pocs_go/tomcat"
	"github.com/hktalent/scan4all/pocs_go/weblogic"
	"github.com/hktalent/scan4all/pocs_go/zabbix"
	"net/url"
)

var noRpt = map[string]string{}

func POCcheck(wappalyzertechnologies []string, URL string, finalURL string, checklog4j bool) []string {
	//if _, ok := noRpt[URL]; ok {
	//	return []string{}
	//}
	noRpt[URL] = "1"
	var HOST string
	var technologies []string
	if host, err := url.Parse(URL); err == nil {
		HOST = host.Host
	}
	for tech := range wappalyzertechnologies {
		switch wappalyzertechnologies[tech] {
		case "Shiro":
			key := shiro.CVE_2016_4437(finalURL)
			if key != "" {
				technologies = append(technologies, fmt.Sprintf("exp-Shiro|key:%s", key))
			}
		case "Apache Tomcat":
			username, password := brute.Tomcat_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("brute-Tomcat|%s:%s", username, password))
			}
			if tomcat.CVE_2020_1938(HOST) {
				technologies = append(technologies, "exp-Tomcat|CVE_2020_1938")
			}
			if tomcat.CVE_2017_12615(URL) {
				technologies = append(technologies, "exp-Tomcat|CVE_2017_12615")
			}
		case "Basic":
			username, password := brute.Basic_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("brute-basic|%s:%s", username, password))
			}
		case "Weblogic", "WebLogic":
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
		case "JBoss", "JBoss Application Server 7", "jboss", "jboss-as", "jboss-eap", "JBoss Web", "JBoss Application Server":
			if jboss.CVE_2017_12149(URL) {
				technologies = append(technologies, "exp-jboss|CVE_2017_12149")
			}
			username, password := brute.Jboss_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("brute-jboss|%s:%s", username, password))
			}
		case "JSON":
			fastjsonRceType := fastjson.Check(URL, finalURL)
			if fastjsonRceType != "" {
				technologies = append(technologies, fmt.Sprintf("exp-FastJson|%s", fastjsonRceType))
			}
		case "Jenkins", "jenkins":
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
		case "ThinkPHP", "thinkphp":
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
		case "LoginPage":
			username, password, loginurl := brute.Admin_brute(finalURL)
			if loginurl != "" {
				technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s", username, password))
			}
		case "Sunlogin":
			if sunlogin.SunloginRCE(URL) {
				technologies = append(technologies, "exp-Sunlogin|RCE")
			}
		case "ZabbixSAML":
			if zabbix.CVE_2022_23131(URL) {
				technologies = append(technologies, "exp-ZabbixSAML|bypass-login")
			}
		case "Spring", "Spring env", "spring-boot", "spring-framework", "spring-boot-admin":
			if Springboot.CVE_2022_22965(finalURL) {
				technologies = append(technologies, "exp-Spring4Shell|CVE_2022_22965")
			}
		case "SpringGateway":
			if Springboot.CVE_2022_22947(URL) {
				technologies = append(technologies, "exp-SpringGateway|CVE_2022_22947")
			}
		case "GitLab":
			if gitlab.CVE_2021_22205(URL) {
				technologies = append(technologies, "exp-gitlab|CVE_2021_22205")
			}
		case "Confluence":
			if confluence.CVE_2021_26084(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2021_26084")
			}
			if confluence.CVE_2021_26085(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2021_26085")
			}
			if confluence.CVE_2022_26134(URL) {
				technologies = append(technologies, "exp-confluence|CVE_2022_26134")
			}
		case "f5 Big IP":
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

	return technologies
}
