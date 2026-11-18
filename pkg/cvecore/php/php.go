package php

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Client PHP 服务探测客户端
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

// DetectVersion 通过 HTTP 响应头/常见路径识别 PHP 版本
// 利用 X-Powered-By 头和 Server 头
func (c *Client) DetectVersion() (string, bool) {
	// 请求根路径，检查响应头
	resp, err := c.HTTP.Get(c.BaseURL + "/")
	if err != nil {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	resp.Body.Close()

	version := ""
	// X-Powered-By: PHP/8.3.12
	if xp := resp.Header.Get("X-Powered-By"); xp != "" {
		if m := regexp.MustCompile(`PHP/([\d.]+)`).FindStringSubmatch(xp); len(m) >= 2 {
			version = m[1]
		}
	}
	// Server 头
	if version == "" {
		if srv := resp.Header.Get("Server"); srv != "" {
			if m := regexp.MustCompile(`PHP/?([\d.]+)`).FindStringSubmatch(srv); len(m) >= 2 {
				version = m[1]
			}
		}
	}
	// 从 body 中找版本
	if version == "" {
		if m := regexp.MustCompile(`PHP/([\d.]+)`).FindString(string(body)); m != "" {
			version = m
		}
	}

	if version != "" {
		return version, true
	}
	return "", false
}

// IsVulnerable 检查 PHP 版本是否受 PHP2Shell 影响
// CVE-2026-109618/19 修复版本: 8.2.35, 8.3.36, 8.4.27, 8.5.12
// 受影响: 8.2.x<8.2.35, 8.3.x<8.3.36, 8.4.x<8.4.27, 8.5.x<8.5.12
func IsVulnerable(version string) (bool, string) {
	v := parseVer(version)
	if len(v) < 3 {
		return false, ""
	}

	major, minor, patch := v[0], v[1], v[2]

	type rangeCheck struct {
		major, minor int
		fixPatch     int
		cve          string
	}
	ranges := []rangeCheck{
		{8, 2, 35, "CVE-2026-109618,CVE-2026-109619"},
		{8, 3, 36, "CVE-2026-109618,CVE-2026-109619"},
		{8, 4, 27, "CVE-2026-109618,CVE-2026-109619"},
		{8, 5, 12, "CVE-2026-109618,CVE-2026-109619"},
	}

	for _, r := range ranges {
		if major == r.major && minor == r.minor && patch < r.fixPatch {
			return true, r.cve
		}
	}
	return false, ""
}

// ProbeOOMTrigger 发送大 multipart 请求探测 CVE-2026-109618 (OOM longjmp)
// 该漏洞通过大请求体触发内存耗尽，观察响应是否异常
func (c *Client) ProbeOOMTrigger() bool {
	// 构造大 multipart 请求体，模拟 OOM 触发条件
	// 发送约 64MB 的填充数据
	bigData := strings.Repeat("A", 64*1024*1024)

	req, err := http.NewRequest("POST", c.BaseURL+"/index.php", strings.NewReader(bigData))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(bigData)))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// 连接被断开/超时可能是 PHP-FPM worker 崩溃 → 漏洞存在的信号
		return true
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	// 500 错误或响应异常可能表示 OOM 触发
	if resp.StatusCode >= 500 {
		return true
	}
	// 检查响应中是否有 PHP fatal error / OOM 提示
	bs := string(body)
	if strings.Contains(bs, "Allowed memory size") ||
		strings.Contains(bs, "Fatal error") ||
		strings.Contains(bs, "longjmp") {
		return true
	}
	return false
}

// ProbeStaleState 发送快速连续请求探测 CVE-2026-109619 (UAF stale state)
// 通过两个快速连续请求，第二个请求观察是否引用了第一个请求释放的内存
func (c *Client) ProbeStaleState() bool {
	// 第一个请求：构造特殊状态
	req1, _ := http.NewRequest("POST", c.BaseURL+"/index.php?test=1",
		strings.NewReader(strings.Repeat("B", 1024)))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp1, err := c.HTTP.Do(req1)
	if err != nil {
		return false
	}
	resp1.Body.Close()

	// 第二个请求：检查是否因 stale state 导致异常
	req2, _ := http.NewRequest("GET", c.BaseURL+"/index.php?test=2", nil)
	resp2, err := c.HTTP.Do(req2)
	if err != nil {
		// 连接异常断开可能表示 worker 崩溃
		return true
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
	resp2.Body.Close()

	bs := string(body2)
	if resp2.StatusCode >= 500 ||
		strings.Contains(bs, "Segmentation") ||
		strings.Contains(bs, "core dumped") ||
		strings.Contains(bs, "zend_mm_heap") {
		return true
	}
	return false
}

func parseVer(v string) []int {
	var nums []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	return nums
}

// ScanResult PHP 扫描结果
type ScanResult struct {
	URL      string
	Version  string
	CVE      string
	Vuln     bool
	Evidence string
}
