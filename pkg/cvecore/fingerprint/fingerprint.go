// Package fingerprint provides a dependency-free web / service fingerprint
// engine modelled after webanalyze and Wappalyzer: it collects HTTP evidence
// (status, headers, cookies, title, body) plus a few targeted deep probes and
// matches it against a built-in rule set. Every detected component is mapped
// to the CVEs this scanner knows how to blind-test, so the scanner can go from
// "fingerprint first" to "only run the mapped exploits" and fall back to the
// full blind set when nothing is recognised.
package fingerprint

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Match is a single detected technology.
type Match struct {
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Weak     bool     `json:"weak,omitempty"` // server/stack layer, never used to narrow the scan
	CVEs     []string `json:"cves,omitempty"`
}

// Result is the fingerprint of one target.
type Result struct {
	Target  string  `json:"target"`
	Matches []Match `json:"matches"`
}

// Probe is one HTTP response used as fingerprint evidence.
type Probe struct {
	Status int
	Header http.Header
	Body   string
	Title  string
	Err    string
}

// Evidence groups the root response, the optional deep probes and the Shiro check.
type Evidence struct {
	Base  *Probe
	Extra map[string]*Probe
	Shiro bool
}

// deepPaths are the extra paths probed to recognise components that do not
// advertise themselves on "/" (WebLogic console, Tomcat manager, Spring
// actuator, Nacos, Metabase, GeoServer, OFBiz, Solr).
var deepPaths = []string{
	"/console/login/LoginForm.jsp",
	"/manager/html",
	"/actuator",
	"/nacos/",
	"/api/session/properties",
	"/geoserver/web/",
	"/webtools/control/main",
	"/solr/",
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Normalize turns "host:port" or "http://host:port" into a clean base URL.
func Normalize(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return t
	}
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		t = "http://" + t
	}
	return strings.TrimRight(t, "/")
}

func newClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			Proxy:             nil,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetch(c *http.Client, u string, headers map[string]string) *Probe {
	p := &Probe{Header: http.Header{}}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; cve-scanner-fingerprint)")
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	defer resp.Body.Close()
	p.Status = resp.StatusCode
	p.Header = resp.Header.Clone()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	p.Body = string(body)
	if m := titleRe.FindStringSubmatch(p.Body); len(m) > 1 {
		p.Title = strings.TrimSpace(m[1])
	}
	return p
}

// followOneHop resolves a single 3xx redirect so frameworks that redirect "/"
// to their real landing page still produce usable evidence.
func followOneHop(c *http.Client, base string, p *Probe) *Probe {
	if p == nil || p.Err != "" || p.Status < 300 || p.Status >= 400 {
		return p
	}
	loc := p.Header.Get("Location")
	if loc == "" {
		return p
	}
	u, err := url.Parse(loc)
	if err != nil {
		return p
	}
	if !u.IsAbs() {
		b, err := url.Parse(base + "/")
		if err != nil {
			return p
		}
		u = b.ResolveReference(u)
	}
	return fetch(c, u.String(), nil)
}

// Collect gathers the evidence used by rule matching.
func Collect(baseURL string, timeout time.Duration, deep bool) *Evidence {
	base := Normalize(baseURL)
	c := newClient(timeout)
	ev := &Evidence{Base: followOneHop(c, base, fetch(c, base+"/", nil)), Extra: make(map[string]*Probe)}
	if !deep {
		return ev
	}
	// Shiro: an invalid rememberMe cookie is answered with rememberMe=deleteMe.
	p := fetch(c, base+"/", map[string]string{"Cookie": "rememberMe=1"})
	for _, ck := range p.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(ck), "rememberme") && strings.Contains(ck, "deleteMe") {
			ev.Shiro = true
			break
		}
	}
	for _, path := range deepPaths {
		ev.Extra[path] = fetch(c, base+path, nil)
	}
	return ev
}

// Detect runs a full (root + deep probes) fingerprint.
func Detect(baseURL string, timeout time.Duration) *Result {
	return detect(baseURL, timeout, true)
}

// QuickDetect only inspects the root response (used by high-concurrency scans).
func QuickDetect(baseURL string, timeout time.Duration) *Result {
	return detect(baseURL, timeout, false)
}

func detect(baseURL string, timeout time.Duration, deep bool) *Result {
	ev := Collect(baseURL, timeout, deep)
	res := &Result{Target: Normalize(baseURL)}
	idx := make(map[string]int)

	for _, r := range rules {
		p := ev.Base
		if r.Path != "" {
			p = ev.Extra[r.Path]
			if p == nil {
				continue
			}
		}
		if r.Shiro && !ev.Shiro {
			continue
		}
		tok, ok := r.match(p)
		if !ok {
			continue
		}
		ver := r.version(p)
		if i, exists := idx[r.Name]; exists {
			if res.Matches[i].Version == "" {
				res.Matches[i].Version = ver
			}
			continue
		}
		idx[r.Name] = len(res.Matches)
		res.Matches = append(res.Matches, Match{
			Name:     r.Name,
			Version:  ver,
			Evidence: tok,
			Weak:     r.Weak,
			CVEs:     ComponentCVEs(r.Name),
		})
	}
	return res
}

// Strong returns the matches that are allowed to narrow the exploit set.
func (r *Result) Strong() []Match {
	if r == nil {
		return nil
	}
	var out []Match
	for _, m := range r.Matches {
		if !m.Weak {
			out = append(out, m)
		}
	}
	return out
}

// HasFingerprint reports whether at least one strong (application-level)
// component was identified.
func (r *Result) HasFingerprint() bool {
	return len(r.Strong()) > 0
}

// Allows reports whether a CVE should be tested for this target. When no
// strong fingerprint exists the scanner falls back to the full blind set.
func (r *Result) Allows(cve string) bool {
	if r == nil || !r.HasFingerprint() {
		return true
	}
	for _, m := range r.Strong() {
		for _, c := range m.CVEs {
			if c == cve {
				return true
			}
		}
	}
	return false
}

// HasComponent reports whether a component-specific check may run. Weak
// fingerprints (nginx/Apache/PHP/Node) never narrow the scan on their own.
func (r *Result) HasComponent(name string) bool {
	if r == nil || !r.HasFingerprint() {
		return true
	}
	for _, m := range r.Strong() {
		if m.Name == name {
			return true
		}
	}
	return false
}

// CVEs returns the sorted union of the CVEs mapped from strong matches.
func (r *Result) CVEs() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range r.Strong() {
		for _, c := range m.CVEs {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Components returns the sorted names of strong matches.
func (r *Result) Components() []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, m := range r.Strong() {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// Summary renders "WebLogic 12.2.1.4, Tomcat 8.5.19" for logs.
func (r *Result) Summary() string {
	if r == nil || len(r.Matches) == 0 {
		return ""
	}
	var parts []string
	for _, m := range r.Matches {
		s := m.Name
		if m.Version != "" {
			s += " " + m.Version
		}
		if m.Weak {
			s += "(weak)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}
