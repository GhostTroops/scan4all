package fingerprint

import (
	"net/http"
	"strings"
	"testing"
)

// 真实 exp 响应里出现组件特征时应当被识别，并带上 CVE 映射。
func TestObserveResponseDetectsComponent(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Apache-Coyote/1.1")
	got := ObserveResponse("/anything", 200, h, []byte("<html><title>Tomcat</title></html>"))
	m, ok := findMatch(&Result{Matches: got}, "Tomcat")
	if !ok {
		t.Fatalf("未从响应中识别到 Tomcat: %+v", got)
	}
	if len(m.CVEs) != 2 {
		t.Fatalf("Tomcat CVEs = %v", m.CVEs)
	}
	if m.Weak {
		t.Fatal("Tomcat 应为 strong 指纹")
	}
}

// 绑定路径的规则只在请求路径匹配时生效。
func TestObserveResponseRespectsRulePath(t *testing.T) {
	body := []byte(`<html><form id="LoginForm"></form></html>`)
	if got := ObserveResponse("/other", 200, nil, body); len(got) != 0 {
		t.Fatalf("非 console 路径不应命中 WebLogic: %+v", got)
	}
	got := ObserveResponse("/console/login/LoginForm.jsp", 200, nil, body)
	if len(got) != 1 || got[0].Name != "WebLogic" {
		t.Fatalf("console 路径应命中 WebLogic: %+v", got)
	}
}

// 404 回显请求路径不能被当成组件指纹。
func TestObserveResponseIgnoresPathEcho(t *testing.T) {
	path := "/struts2-showcase/index.action"
	body := []byte("404 Not Found: " + path)
	if got := ObserveResponse(path, 404, nil, body); len(got) != 0 {
		t.Fatalf("路径回显被误判: %+v", got)
	}
}

// Shiro 通过 rememberMe=deleteMe 响应头识别。
func TestObserveResponseShiro(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")
	got := ObserveResponse("/", 200, h, []byte("home"))
	if len(got) != 1 || got[0].Name != "Shiro" {
		t.Fatalf("未识别到 Shiro: %+v", got)
	}
	if len(got[0].CVEs) == 0 {
		t.Fatal("Shiro 应带 CVE 映射")
	}
}

// Merge 只追加新组件，已存在的组件保留原版本信息。
func TestResultMerge(t *testing.T) {
	res := &Result{Matches: []Match{{Name: "Tomcat", Version: "8.5.19", Weak: false}}}
	added := res.Merge([]Match{
		{Name: "Tomcat", Version: "9.0.1"},
		{Name: "Struts2"},
	})
	if len(added) != 1 || added[0].Name != "Struts2" {
		t.Fatalf("added = %+v", added)
	}
	if res.Matches[0].Version != "8.5.19" {
		t.Fatalf("已有组件版本被覆盖: %+v", res.Matches[0])
	}
	if !res.HasComponent("Struts2") {
		t.Fatal("合并后应包含 Struts2")
	}
	if !strings.Contains(res.Summary(), "Struts2") {
		t.Fatalf("Summary 未包含新组件: %s", res.Summary())
	}
}
