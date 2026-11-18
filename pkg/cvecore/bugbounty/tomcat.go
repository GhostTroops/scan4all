package bugbounty

import (
	"fmt"
	"net/http"
	"strings"
)

// ============================================================
// CVE-2017-12615 Tomcat PUT method RCE
// ============================================================
func ProbeTomcatPUT(base string) *Finding {
	req, _ := http.NewRequest("PUT", base+"/bbtest.jsp", strings.NewReader("test"))
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		code, body, _, _ := Get(base + "/bbtest.jsp")
		if code == 200 && strings.Contains(body, "test") {
			return &Finding{Target: base, Vuln: "CVE-2017-12615 Tomcat PUT RCE", Severity: "CRITICAL",
				Detail: "file uploaded and accessible", URL: base + "/bbtest.jsp"}
		}
	}
	return nil
}

// ============================================================
// CVE-2025-24813 Tomcat Partial PUT
// ============================================================
func ProbeTomcat24813(base string) *Finding {
	_, _, hdr, err := Get(base + "/")
	if err != nil {
		return nil
	}
	server := hdr.Get("Server")
	if !strings.Contains(server, "Tomcat") {
		return nil
	}
	req, _ := http.NewRequest("PUT", base+"/bbtest", strings.NewReader("test"))
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	if resp.StatusCode == 201 || resp.StatusCode == 204 || resp.StatusCode == 409 {
		return &Finding{Target: base, Vuln: "CVE-2025-24813 Tomcat Partial PUT (potential)", Severity: "HIGH",
			Detail: fmt.Sprintf("Server: %s, PUT allowed: %d", server, resp.StatusCode), URL: base}
	}
	return nil
}
