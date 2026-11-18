package fingerprint

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testTimeout = 2 * time.Second

// newTestServer 按路径分发响应，未注册路径统一返回 404。
func newTestServer(routes map[string]http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404 page not found")
	}))
}

func findMatch(res *Result, name string) (Match, bool) {
	for _, m := range res.Matches {
		if m.Name == name {
			return m, true
		}
	}
	return Match{}, false
}

// WebLogic 仅通过 console 深度探测识别，并提取版本。
func TestDetectWebLogicConsole(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/console/login/LoginForm.jsp": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>WebLogic Server 12.2.1.4</title><form id="LoginForm"></form></html>`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	m, ok := findMatch(res, "WebLogic")
	if !ok {
		t.Fatalf("未识别到 WebLogic，matches=%+v", res.Matches)
	}
	if m.Version != "12.2.1.4" {
		t.Fatalf("WebLogic 版本 = %q, want 12.2.1.4", m.Version)
	}
	if !res.HasFingerprint() {
		t.Fatal("WebLogic 应视为 strong 指纹")
	}
	if !res.Allows("CVE-2026-70748") {
		t.Fatal("WebLogic 指纹应允许 CVE-2026-70748")
	}
	if res.Allows("CVE-2017-12615") {
		t.Fatal("WebLogic 指纹不应允许 Tomcat CVE-2017-12615")
	}
	if !res.HasComponent("WebLogic") || res.HasComponent("Tomcat") {
		t.Fatal("HasComponent 过滤不正确")
	}
}

// 404 页面回显请求路径时不得误判为 WebLogic/GeoServer/Nacos 等组件。
func TestNoFingerprintOn404PathEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404 Not Found: "+r.URL.Path)
	}))
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if len(res.Matches) != 0 {
		t.Fatalf("404 回显被误判: %+v", res.Matches)
	}
	if res.HasFingerprint() {
		t.Fatal("无指纹时 HasFingerprint 应为 false")
	}
	if !res.Allows("CVE-2016-4437") {
		t.Fatal("无指纹时必须回退全量，Allows 应恒为 true")
	}
}

// 只有 weak 指纹（nginx）时不能收窄 exp 集合。
func TestWeakOnlyDoesNotNarrow(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx/1.25.3")
			io.WriteString(w, `<html><title>Welcome</title></html>`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	m, ok := findMatch(res, "nginx")
	if !ok || !m.Weak {
		t.Fatalf("nginx 应为 weak 指纹，matches=%+v", res.Matches)
	}
	if m.Version != "1.25.3" {
		t.Fatalf("nginx 版本 = %q, want 1.25.3", m.Version)
	}
	if res.HasFingerprint() {
		t.Fatal("仅 weak 指纹时 HasFingerprint 应为 false")
	}
	if len(res.CVEs()) != 0 {
		t.Fatalf("weak 指纹不应产生强 CVE 列表: %v", res.CVEs())
	}
	if !res.Allows("CVE-2016-4437") || !res.HasComponent("Shiro") {
		t.Fatal("仅 weak 指纹时应回退全量 exp")
	}
	if !strings.Contains(res.Summary(), "(weak)") {
		t.Fatalf("Summary 未标注 weak: %s", res.Summary())
	}
}

// strong 指纹（Tomcat）只允许组件映射的 CVE。
func TestStrongFingerprintNarrowsCVEs(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache-Coyote/1.1")
			io.WriteString(w, `<html><title>Tomcat</title></html>`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(res, "Tomcat"); !ok {
		t.Fatalf("未识别到 Tomcat，matches=%+v", res.Matches)
	}
	cves := res.CVEs()
	if len(cves) != 2 || cves[0] != "CVE-2017-12615" || cves[1] != "CVE-2025-24813" {
		t.Fatalf("Tomcat CVE 映射 = %v", cves)
	}
	if !res.Allows("CVE-2017-12615") || res.Allows("CVE-2016-4437") {
		t.Fatal("strong 指纹过滤不正确")
	}
	if !res.HasComponent("Tomcat") || res.HasComponent("Shiro") {
		t.Fatal("HasComponent 过滤不正确")
	}
}

// Shiro 通过 rememberMe=deleteMe 主动探测识别。
func TestDetectShiro(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Cookie"), "rememberMe=1") {
				w.Header().Set("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
				io.WriteString(w, "home")
				return
			}
			io.WriteString(w, `<html><title>Home</title></html>`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(res, "Shiro"); !ok {
		t.Fatalf("未识别到 Shiro，matches=%+v", res.Matches)
	}
	if !res.Allows("CVE-2016-4437") {
		t.Fatal("Shiro 指纹应允许 CVE-2016-4437")
	}
}

// 首页 3xx 跳转后应基于落地页做指纹匹配。
func TestFollowOneHopRedirect(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/orders.xhtml")
			w.WriteHeader(http.StatusSeeOther)
			io.WriteString(w, "/orders.xhtml")
		},
		"/orders.xhtml": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `<html><title>Orders</title><h1>Struts REST Showcase</h1></html>`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(res, "Struts2"); !ok {
		t.Fatalf("跳转后未识别到 Struts2，matches=%+v", res.Matches)
	}
	if !res.Allows("CVE-2017-9805") {
		t.Fatal("Struts2 指纹应允许 CVE-2017-9805")
	}
}

// ActiveMQ 通过 401 + WWW-Authenticate 识别。
func TestDetectActiveMQ(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="ActiveMQRealm"`)
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "Unauthorized")
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(res, "ActiveMQ"); !ok {
		t.Fatalf("未识别到 ActiveMQ，matches=%+v", res.Matches)
	}
	if !res.Allows("CVE-2026-34197") || res.Allows("CVE-2016-4437") {
		t.Fatal("ActiveMQ 指纹过滤不正确")
	}
}

// Spring Boot Actuator 通过深度路径识别。
func TestDetectSpringActuator(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/actuator": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			io.WriteString(w, `{"_links":{"self":{"href":"/actuator"}}}`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(res, "Spring"); !ok {
		t.Fatalf("未识别到 Spring，matches=%+v", res.Matches)
	}
	if !res.Allows("CVE-2022-22965") {
		t.Fatal("Spring 指纹应允许 CVE-2022-22965")
	}
}

// Metabase 通过 /api/session/properties 识别。
func TestDetectMetabase(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"/api/session/properties": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"setup-token":"abc","metabase":true}`)
		},
	})
	defer srv.Close()

	res := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(res, "Metabase"); !ok {
		t.Fatalf("未识别到 Metabase，matches=%+v", res.Matches)
	}
	if !res.Allows("CVE-2023-38646") {
		t.Fatal("Metabase 指纹应允许 CVE-2023-38646")
	}
}

// QuickDetect 只请求根路径，不执行深度探测。
func TestQuickDetectSkipsDeepProbes(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		if r.URL.Path == "/actuator" {
			io.WriteString(w, `{"_links":{"self":{"href":"/actuator"}}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404 page not found")
	}))
	defer srv.Close()

	quick := QuickDetect(srv.URL, testTimeout)
	if len(quick.Matches) != 0 {
		t.Fatalf("QuickDetect 不应命中深度探测组件: %+v", quick.Matches)
	}
	quickCount := atomic.LoadInt64(&requests)
	if quickCount != 1 {
		t.Fatalf("QuickDetect 请求数 = %d, want 1", quickCount)
	}

	full := Detect(srv.URL, testTimeout)
	if _, ok := findMatch(full, "Spring"); !ok {
		t.Fatalf("Detect 应命中 Actuator，matches=%+v", full.Matches)
	}
	if atomic.LoadInt64(&requests) <= quickCount {
		t.Fatal("Detect 应执行深度探测")
	}
}

// ComponentCVEs 必须返回副本，避免调用方篡改映射表。
func TestComponentCVEsReturnsCopy(t *testing.T) {
	got := ComponentCVEs("Tomcat")
	if len(got) != 2 {
		t.Fatalf("Tomcat CVE 数量 = %d, want 2", len(got))
	}
	got[0] = "MUTATED"
	if again := ComponentCVEs("Tomcat"); again[0] == "MUTATED" {
		t.Fatal("ComponentCVEs 返回了映射表内部切片")
	}
	if ComponentCVEs("NoSuchComponent") != nil {
		t.Fatal("未知组件应返回 nil")
	}
}
