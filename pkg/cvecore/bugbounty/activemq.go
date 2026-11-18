package bugbounty

import "strings"

func ProbeActiveMQ(base string) *Finding {
	code, body, _, err := Get(base + "/admin/")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "ActiveMQ") {
		return &Finding{Target: base, Vuln: "CVE-2026-34197 ActiveMQ Jolokia (detected)", Severity: "CRITICAL",
			Detail: "ActiveMQ admin console exposed", URL: base + "/admin/"}
	}
	code2, body2, _, _ := Get(base + "/api/jolokia/")
	if code2 == 200 && strings.Contains(body2, "jolokia") {
		return &Finding{Target: base, Vuln: "ActiveMQ Jolokia API Exposed", Severity: "CRITICAL",
			Detail: "/api/jolokia/ accessible", URL: base + "/api/jolokia/"}
	}
	return nil
}
