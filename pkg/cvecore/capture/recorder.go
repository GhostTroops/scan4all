// Package capture records the HTTP payloads sent by exploits so they can be
// fingerprinted and, when nothing succeeded, replayed through an HTTP
// smuggling channel. It also observes every exploit/smuggling response for
// component evidence so the scan can expand its exploit set mid-flight.
package capture

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/GhostTroops/scan4all/pkg/cvecore/fingerprint"
)

const (
	recordBodyLimit = 1 << 20
	recordRespLimit = 8192
)

// Request is one HTTP payload the probes actually sent, together with the
// direct response, so it can be replayed through a smuggling channel later.
type Request struct {
	Method   string
	URL      string
	Scheme   string
	HostHdr  string
	Path     string
	Query    string
	Header   http.Header
	Body     []byte
	Status   int
	RespBody []byte
}

// Finding is a smuggling-replay result.
type Finding struct {
	Target   string `json:"target"`
	Vuln     string `json:"vuln"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	URL      string `json:"url"`
}

// Recorder is a RoundTripper that remembers every non-trivial probe request,
// observes all responses for fingerprints, and tracks which components were
// already known before the scan started.
type Recorder struct {
	base     http.RoundTripper
	mu       sync.Mutex
	byKey    map[string][]*Request
	observed map[string][]fingerprint.Match
	baseline map[string]map[string]bool
}

// NewRecorder wraps base. A nil base uses http.DefaultTransport.
func NewRecorder(base http.RoundTripper) *Recorder {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Recorder{
		base:     base,
		byKey:    make(map[string][]*Request),
		observed: make(map[string][]fingerprint.Match),
		baseline: make(map[string]map[string]bool),
	}
}

// HostKey normalizes a URL to host:port so concurrent targets do not interfere.
func HostKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// KeyForBase returns the recorder key for a base URL such as
// "http://127.0.0.1:8080".
func KeyForBase(raw string) string {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return raw
	}
	return HostKey(u)
}

// shouldRecord keeps every real payload, including GET-based exploits, while
// skipping bare discovery GETs of "/" that only check reachability.
func shouldRecord(req *http.Request, body []byte) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return true
	}
	if len(body) > 0 || req.Header.Get("Cookie") != "" || req.URL.RawQuery != "" {
		return true
	}
	return req.URL.Path != "" && req.URL.Path != "/"
}

func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, recordBodyLimit))
		req.Body.Close()
		if err == nil {
			body = b
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	key := HostKey(req.URL)

	var rec *Request
	if shouldRecord(req, body) {
		rec = &Request{
			Method:  req.Method,
			URL:     req.URL.String(),
			Scheme:  req.URL.Scheme,
			HostHdr: req.Host,
			Path:    req.URL.Path,
			Query:   req.URL.RawQuery,
			Header:  req.Header.Clone(),
			Body:    body,
		}
	}

	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if rec != nil {
		rec.Status = resp.StatusCode
		r.mu.Lock()
		r.byKey[key] = append(r.byKey[key], rec)
		r.mu.Unlock()
	}
	resp.Body = &observingBody{
		inner:   resp.Body,
		rec:     r,
		key:     key,
		path:    req.URL.Path,
		status:  resp.StatusCode,
		header:  resp.Header.Clone(),
		payload: rec,
	}
	return resp, nil
}

// observingBody collects the first bytes of the response so the recorder can
// fingerprint it, and backfills the replay payload's captured response.
type observingBody struct {
	inner   io.ReadCloser
	rec     *Recorder
	key     string
	path    string
	status  int
	header  http.Header
	payload *Request
	body    []byte
	once    sync.Once
}

func (b *observingBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	if n > 0 {
		b.rec.mu.Lock()
		room := recordRespLimit - len(b.body)
		if room > 0 {
			if room > n {
				room = n
			}
			b.body = append(b.body, p[:room]...)
		}
		b.rec.mu.Unlock()
	}
	return n, err
}

func (b *observingBody) Close() error {
	b.once.Do(func() {
		b.rec.mu.Lock()
		observed := append([]byte(nil), b.body...)
		if b.payload != nil {
			b.payload.RespBody = observed
		}
		b.rec.mu.Unlock()
		b.rec.Observe(b.key, b.path, b.status, b.header, observed)
	})
	return b.inner.Close()
}

// Observe feeds one response into the fingerprint rules and stores any new
// component evidence for the target key.
func (r *Recorder) Observe(key, path string, status int, header http.Header, body []byte) {
	matches := fingerprint.ObserveResponse(path, status, header, body)
	if len(matches) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range matches {
		if i := matchIndex(r.observed[key], m.Name); i >= 0 {
			if r.observed[key][i].Version == "" {
				r.observed[key][i].Version = m.Version
			}
			continue
		}
		r.observed[key] = append(r.observed[key], m)
	}
}

// ObserveRaw parses a raw smuggled response stream and feeds it to the
// fingerprint engine. The stream may contain several concatenated responses;
// the first header block is used and the whole stream is scanned as body text.
func (r *Recorder) ObserveRaw(key, path, raw string) {
	status := 0
	header := make(http.Header)
	body := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head := raw[:i]
		body = raw[i+4:]
		lines := strings.Split(head, "\r\n")
		if len(lines) > 0 {
			f := strings.SplitN(lines[0], " ", 3)
			if len(f) >= 2 {
				status, _ = strconv.Atoi(f[1])
			}
		}
		for _, ln := range lines[1:] {
			j := strings.Index(ln, ":")
			if j <= 0 {
				continue
			}
			header.Add(strings.TrimSpace(ln[:j]), strings.TrimSpace(ln[j+1:]))
		}
	}
	r.Observe(key, path, status, header, []byte(body))
}

// MarkBaseline records the strong components known before the scan, so later
// observations can be diffed. Weak fingerprints are never diffed.
func (r *Recorder) MarkBaseline(key string, components []fingerprint.Match) {
	set := make(map[string]bool, len(components))
	for _, m := range components {
		if !m.Weak {
			set[m.Name] = true
		}
	}
	r.mu.Lock()
	r.baseline[key] = set
	r.mu.Unlock()
}

// NewSinceBaseline returns strong components observed after MarkBaseline.
func (r *Recorder) NewSinceBaseline(key string) []fingerprint.Match {
	r.mu.Lock()
	defer r.mu.Unlock()
	known := r.baseline[key]
	var out []fingerprint.Match
	for _, m := range r.observed[key] {
		if m.Weak || known[m.Name] {
			continue
		}
		out = append(out, m)
	}
	return out
}

// TakeAll empties the recorder and returns the captured payloads per host.
func (r *Recorder) TakeAll() map[string][]*Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.byKey
	r.byKey = make(map[string][]*Request)
	return out
}

func matchIndex(list []fingerprint.Match, name string) int {
	for i := range list {
		if list[i].Name == name {
			return i
		}
	}
	return -1
}

// buildRawRequest rebuilds a raw HTTP/1.1 request from a captured payload.
func buildRawRequest(c *Request, hostHeader string) []byte {
	var b strings.Builder
	path := c.Path
	if path == "" {
		path = "/"
	}
	b.WriteString(c.Method)
	b.WriteString(" ")
	b.WriteString(path)
	if c.Query != "" {
		b.WriteString("?")
		b.WriteString(c.Query)
	}
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(hostHeader)
	b.WriteString("\r\n")
	for k, vs := range c.Header {
		switch strings.ToLower(k) {
		case "host", "content-length", "transfer-encoding", "connection":
			continue
		}
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(c.Body)))
	b.WriteString("\r\n\r\n")
	b.WriteString(string(c.Body))
	return []byte(b.String())
}
