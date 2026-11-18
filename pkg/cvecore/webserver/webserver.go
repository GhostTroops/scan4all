package webserver

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Client Web 服务器探测客户端
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
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

// Fingerprint 识别 Web 服务器类型和版本
type Fingerprint struct {
	Server  string // nginx / Apache / Microsoft-IIS / Node.js
	Version string
}

func (c *Client) Fingerprint() (*Fingerprint, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/")
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	resp.Body.Close()

	fp := &Fingerprint{}
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	// NGINX
	if m := regexp.MustCompile(`nginx/?([\d.]+)?`).FindStringSubmatch(server); len(m) >= 1 {
		fp.Server = "nginx"
		if len(m) >= 2 {
			fp.Version = m[1]
		}
	}

	// Apache
	if strings.Contains(server, "Apache") || strings.Contains(server, "httpd") {
		fp.Server = "Apache"
		if m := regexp.MustCompile(`Apache(?:/[\s]?httpd)?/([\d.]+)`).FindStringSubmatch(server); len(m) >= 2 {
			fp.Version = m[1]
		}
	}

	// Node.js
	if strings.Contains(poweredBy, "Express") || strings.Contains(poweredBy, "Node") ||
		strings.Contains(server, "Node") || strings.Contains(string(body), "Node.js") {
		fp.Server = "Node.js"
		if m := regexp.MustCompile(`Node\.js[/ ]([\d.]+)`).FindStringSubmatch(server + " " + poweredBy); len(m) >= 2 {
			fp.Version = m[1]
		}
	}

	// HTTP.sys (Windows) - 通过响应特征判断
	if strings.Contains(server, "Microsoft-HTTPAPI") {
		fp.Server = "HTTP.sys"
	}

	return fp, nil
}

// CheckVulns 检查指纹对应的漏洞
func CheckVulns(fp *Fingerprint) []string {
	var vulns []string

	switch fp.Server {
	case "nginx":
		// CVE-2026-42945: NGINX rewrite heap overflow, affects 0.6.27-1.30.0
		// CVE-2026-42533: NGINX heap overflow
		// CVE-2026-15176: NGINX HTTP/3 heap overflow
		// CVE-2026-93479: NGINX map directive heap overflow
		if v := parseVer(fp.Version); len(v) >= 2 {
			if v[0] < 1 || (v[0] == 1 && v[1] <= 30) {
				vulns = append(vulns, "CVE-2026-42945", "CVE-2026-42533",
					"CVE-2026-15176", "CVE-2026-93479")
			}
		}
	case "Apache":
		// CVE-2026-23918: Apache 2.4.66 HTTP/2 double-free
		if fp.Version == "2.4.66" {
			vulns = append(vulns, "CVE-2026-23918")
		}
	case "Node.js":
		// CVE-2026-111497 (Node2Shell): Brotli OOB write
		// All supported Node.js versions affected, fixed Oct 21 2026
		vulns = append(vulns, "CVE-2026-111497")
	}

	return vulns
}

// ProbeNGINXOverflow 发送 NGINX rewrite/map 溢出探测包
func (c *Client) ProbeNGINXOverflow() bool {
	// 发送特殊构造的 URI 触发 rewrite/map 模块
	payloads := []string{
		"/$1?$1",
		"/a%00%00%00%00%00%00%00",
		"/" + strings.Repeat("A", 8192) + "?$1",
	}
	for _, p := range payloads {
		resp, err := c.HTTP.Get(c.BaseURL + p)
		if err != nil {
			return true // 连接断开 = worker crash
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return true
		}
	}
	return false
}

// ProbeApacheHTTP2 探测 Apache 2.4.66 HTTP/2 双释放
func (c *Client) ProbeApacheHTTP2() bool {
	// 发送 HTTP/2 升级请求
	req, _ := http.NewRequest("GET", c.BaseURL+"/", nil)
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
	req.Header.Set("HTTP2-Settings", strings.Repeat("A", 1024))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return true
	}
	resp.Body.Close()
	return false
}

// ProbeNodeBrotli 探测 Node2Shell (Brotli OOB write)
// 发送 Accept-Encoding: br，观察是否处理 Brotli
func (c *Client) ProbeNodeBrotli() bool {
	req, _ := http.NewRequest("GET", c.BaseURL+"/", nil)
	req.Header.Set("Accept-Encoding", "br")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return true
	}
	encoding := resp.Header.Get("Content-Encoding")
	resp.Body.Close()
	return strings.Contains(encoding, "br")
}

// ProbeWindowsHTTPStack 探测 IIS/HTTP.sys 缓冲区溢出
func parseVer(v string) []int {
	var nums []int
	for _, part := range strings.Split(v, ".") {
		var n int
		fmt.Sscanf(part, "%d", &n)
		nums = append(nums, n)
	}
	return nums
}
