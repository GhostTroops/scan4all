package capture

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/GhostTroops/scan4all/pkg/cvecore/fingerprint"
)

// 采集器应记录真实 exp payload 及其直连响应。
func TestRecorderCapturesPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "blocked:"+string(body))
	}))
	defer srv.Close()

	rec := NewRecorder(http.DefaultTransport)
	c := &http.Client{Transport: rec}

	req, _ := http.NewRequest("POST", srv.URL+"/api/setup/validate?x=1", strings.NewReader(`{"a":1}`))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	buckets := rec.TakeAll()
	reqs := buckets[KeyForBase(srv.URL)]
	if len(reqs) != 1 {
		t.Fatalf("captured = %d, want 1", len(reqs))
	}
	got := reqs[0]
	if got.Method != "POST" || got.Path != "/api/setup/validate" || got.Query != "x=1" {
		t.Fatalf("请求记录不正确: %+v", got)
	}
	if string(got.Body) != `{"a":1}` {
		t.Fatalf("body = %q", got.Body)
	}
	if got.Status != http.StatusForbidden || !strings.Contains(string(got.RespBody), "blocked") {
		t.Fatalf("响应记录不正确: status=%d body=%q", got.Status, got.RespBody)
	}
}

// 普通探测 GET 不应占用回放名额。
func TestRecorderSkipsPlainGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	rec := NewRecorder(http.DefaultTransport)
	c := &http.Client{Transport: rec}
	if _, err := c.Get(srv.URL + "/"); err != nil {
		t.Fatal(err)
	}
	if got := rec.TakeAll(); len(got) != 0 {
		t.Fatalf("plain GET 被记录: %+v", got)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("Cookie", "rememberMe=1")
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	buckets := rec.TakeAll()
	if len(buckets) != 1 || len(buckets[KeyForBase(srv.URL)]) != 1 {
		t.Fatalf("带 Cookie 的 GET 应被记录: %+v", buckets)
	}
}

// 重建的原始请求必须长度正确，且不重复 hop-by-hop 头。
func TestBuildRawRequest(t *testing.T) {
	rec := &Request{
		Method:  "POST",
		Path:    "/api/setup/validate",
		Query:   "x=1",
		HostHdr: "127.0.0.1:8080",
		Header: http.Header{
			"Content-Type":      {"application/json"},
			"Content-Length":    {"99"},
			"Transfer-Encoding": {"chunked"},
			"Connection":        {"keep-alive"},
		},
		Body: []byte(`{"a":1}`),
	}
	raw := string(buildRawRequest(rec, "127.0.0.1:8080"))
	if !strings.HasPrefix(raw, "POST /api/setup/validate?x=1 HTTP/1.1\r\n") {
		t.Fatalf("请求行错误: %q", raw)
	}
	if !strings.Contains(raw, "Content-Length: 7\r\n") {
		t.Fatalf("Content-Length 未重算: %q", raw)
	}
	if strings.Contains(strings.ToLower(raw), "transfer-encoding") {
		t.Fatalf("不应保留 Transfer-Encoding: %q", raw)
	}
	if strings.Count(raw, "Host: ") != 1 {
		t.Fatalf("Host 头重复: %q", raw)
	}
}

// CL.TE 与 TE.CL 包装的长度计算必须自洽，否则无法触发 desync。
func TestSmugglingPayloadShape(t *testing.T) {
	smuggled := []byte("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
	p := smuggledPerm{Name: "default", TEKey: "Transfer-Encoding:", TEValue: "chunked"}

	clte := smugglingPayload(p, "CL.TE", "x", smuggled, "abcd")
	if want := len("0\r\n\r\n") + len(smuggled); !strings.Contains(clte, "Content-Length: "+strconv.Itoa(want)+"\r\n") {
		t.Fatalf("CL.TE Content-Length 错误: %q", clte)
	}
	if !strings.HasSuffix(clte, "0\r\n\r\n"+string(smuggled)) {
		t.Fatalf("CL.TE body 结构错误: %q", clte)
	}

	tecl := smugglingPayload(p, "TE.CL", "x", smuggled, "abcd")
	sizeLine := fmt.Sprintf("%x\r\n", len(smuggled))
	if !strings.Contains(tecl, "Content-Length: "+strconv.Itoa(len(sizeLine))+"\r\n") {
		t.Fatalf("TE.CL Content-Length 应为 chunk-size 行长度: %q", tecl)
	}
	if !strings.Contains(tecl, sizeLine+string(smuggled)) {
		t.Fatalf("TE.CL body 结构错误: %q", tecl)
	}
	if !strings.Contains(tecl, "\r\n\r\n0\r\n\r\n") {
		t.Fatalf("TE.CL 缺少结束块: %q", tecl)
	}
}

// 普通 exp 响应里出现的新组件要被观察为 baseline 之外的指纹。
func TestRecorderObservesNewFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		io.WriteString(w, "<html><title>Tomcat Manager</title></html>")
	}))
	defer srv.Close()

	rec := NewRecorder(http.DefaultTransport)
	key := KeyForBase(srv.URL)
	rec.MarkBaseline(key, nil)

	c := &http.Client{Transport: rec}
	resp, err := c.Get(srv.URL + "/manager/html")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	newMatches := rec.NewSinceBaseline(key)
	if len(newMatches) == 0 || newMatches[0].Name != "Tomcat" {
		t.Fatalf("未观察到 Tomcat: %+v", newMatches)
	}
}

// 已在 baseline 里的组件不算新增，后续才出现的组件才算。
func TestRecorderBaselineDiff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<html><h1>Struts REST Showcase</h1></html>`)
	}))
	defer srv.Close()

	rec := NewRecorder(http.DefaultTransport)
	key := KeyForBase(srv.URL)
	rec.MarkBaseline(key, []fingerprint.Match{{Name: "Tomcat"}})

	c := &http.Client{Transport: rec}
	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	newMatches := rec.NewSinceBaseline(key)
	if len(newMatches) != 1 || newMatches[0].Name != "Struts2" {
		t.Fatalf("NewSinceBaseline = %+v", newMatches)
	}
}

// 走私响应流也能被解析并观察出指纹。
func TestObserveRaw(t *testing.T) {
	rec := NewRecorder(http.DefaultTransport)
	raw := "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Length: 24\r\n\r\n<html>Tomcat Manager</html>"
	rec.MarkBaseline("127.0.0.1:8080", nil)
	rec.ObserveRaw("127.0.0.1:8080", "/manager/html", raw)
	got := rec.NewSinceBaseline("127.0.0.1:8080")
	if len(got) == 0 || got[0].Name != "Tomcat" {
		t.Fatalf("走私响应未识别到 Tomcat: %+v", got)
	}
}
