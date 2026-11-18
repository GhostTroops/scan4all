// Package cvescan 把 cve-scanner 中已验证的 CVE 指纹识别 / 漏洞利用能力接入 scan4all 主流程。
//
// 设计要点：
//   - 默认关闭，必须显式开启（enableCveScan=true 或 -cve 参数），因为其中包含大量主动利用（RCE）动作；
//   - 只把「有真实命令回显」的结果当作漏洞上报，盲打/版本命中只在 verbose 下作为提示输出；
//   - 输入直接复用 naabu/httpx 流水线的结果缓冲区，无需落盘。
package cvescan

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg/cvecore/scanner"
	"github.com/projectdiscovery/gologger"
)

// maxTargets 单次 CVE 扫描最多处理的目标数，避免在内网大段段扫描时被拖死
const maxTargets = 500

// runMu 保证同一时刻只有一次 CVE 扫描在跑（cve 核心内部有全局 transport 状态）
var runMu sync.Mutex

var enableOnce sync.Once

// Enabled 是否启用 CVE 扫描：config/config.json 的 enableCveScan，或命令行 -cve
func Enabled() bool {
	enableOnce.Do(func() {
		if !util.GetValAsBool("enableCveScan") {
			util.LogOnce("cve-scan-off", "[*] CVE 主动扫描未开启（配置 enableCveScan=true 或使用 -cve 参数可开启）")
		}
	})
	if util.GetValAsBool("enableCveScan") {
		return true
	}
	if m, ok := util.G_Options.(map[string]interface{}); ok {
		if b, ok2 := m["EnableCveScan"].(bool); ok2 && b {
			return true
		}
	}
	return false
}

// Options 从 scan4all 配置读取的 CVE 扫描参数
func Options() scanner.Options {
	return scanner.Options{
		Threads:  util.GetValAsInt("cveScanThreads", 20),
		Timeout:  time.Duration(util.GetValAsInt("cveScanTimeout", 8)) * time.Second,
		Cmd:      util.GetValByDefault("cveScanCmd", "hostname"),
		Lhost:    util.GetVal("cveScanLhost"),
		ScanWLS:  util.GetValByDefault("cveScanWls", "true") == "true",
		ScanPHP:  util.GetValByDefault("cveScanPhp", "true") == "true",
		ScanWeb:  util.GetValByDefault("cveScanWeb", "true") == "true",
		ScanApps: util.GetValByDefault("cveScanApps", "true") == "true",
	}
}

// TargetsFromBuffer 把 naabu/httpx 的中间结果解析成 host:port 形式的目标列表
func TargetsFromBuffer(buf *bytes.Buffer) []string {
	if nil == buf || 0 == buf.Len() {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if "" == line || strings.HasPrefix(line, "#") {
			continue
		}
		// httpx 输出可能是 http(s)://host:port/path，需要还原成 host:port
		raw := line
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if nil != err || "" == u.Host {
			continue
		}
		hostPort := u.Host
		if "" == u.Port() {
			if "https" == u.Scheme {
				hostPort = u.Hostname() + ":443"
			} else {
				hostPort = u.Hostname() + ":80"
			}
		}
		if _, ok := seen[hostPort]; ok {
			continue
		}
		seen[hostPort] = struct{}{}
		out = append(out, hostPort)
	}
	return out
}

// Run 对缓冲区中的目标执行指纹驱动的 CVE 扫描，结果并入 scan4all 统一输出
func Run(buf *bytes.Buffer) {
	if !Enabled() {
		return
	}
	targets := TargetsFromBuffer(buf)
	if 0 == len(targets) {
		return
	}
	if len(targets) > maxTargets {
		gologger.Info().Msgf("CVE 扫描目标数 %d 超过上限 %d，仅处理前 %d 个", len(targets), maxTargets, maxTargets)
		targets = targets[:maxTargets]
	}

	runMu.Lock()
	defer runMu.Unlock()

	opt := Options()
	results, err := scanner.RunTargets(targets, opt)
	if nil != err {
		gologger.Warning().Msgf("CVE 扫描异常: %v", err)
		return
	}

	var verified, blind int
	for _, r := range results {
		if scanner.IsVerified(r) {
			verified++
			msg := fmt.Sprintf("%s %s cmd=%s output=%s", r.URL, r.CVE, r.Cmd, strings.TrimSpace(r.Output))
			util.SendLog(r.URL, "CVE", msg, r.Version)
			continue
		}
		blind++
		if util.GetValAsBool("verbose") {
			gologger.Info().Msgf("[blind] %s %s version=%s", r.URL, r.CVE, r.Version)
		}
	}
	gologger.Info().Msgf("CVE 扫描完成：目标 %d，已验证 %d，待人工确认 %d", len(targets), verified, blind)
}
