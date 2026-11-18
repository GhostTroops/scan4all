package fingerprint

import (
	"net/http"
	"regexp"
	"strings"
)

// segStripRe 大小写不敏感地匹配路径片段字面量，用于剥离错误页的路径回显
func segStripRe(seg string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + regexp.QuoteMeta(seg))
}

// ObserveResponse evaluates the built-in rules against a real response captured
// from an exploit or smuggling request. Rules bound to a specific path only fire
// when the request path matches; path-less rules fire on any response. Matches
// are deduplicated by component name and carry the mapped CVE list, so a scan
// can expand its exploit set mid-flight when a later response exposes a
// component the first fingerprint pass missed.
func ObserveResponse(path string, status int, header http.Header, body []byte) []Match {
	if header == nil {
		header = make(http.Header)
	}
	text := string(body)
	// A 404 page that merely echoes the requested path must not look like the
	// component lives at that path (same guard as the deep-path probes).
	if path != "" && path != "/" {
		text = strings.ReplaceAll(text, path, "")
		// 错误页还会以 "action name geoserver"（无斜杠）等形式回显路径片段，
		// 3xx 默认页同样会在 body 回显 Location 目标 URL（含路径片段，可能大小写不同），
		// 而 Body 规则是大小写不敏感匹配，会据此误报组件。仅在非 200 状态下
		// 剥离长度≥4的路径片段（真实组件页为 200，不受影响）。
		if status >= 300 {
			for _, seg := range strings.Split(path, "/") {
				if len(seg) >= 4 {
					text = segStripRe(seg).ReplaceAllString(text, "")
				}
			}
		}
	}
	p := &Probe{Status: status, Header: header, Body: text}
	if m := titleRe.FindStringSubmatch(p.Body); len(m) > 1 {
		p.Title = strings.TrimSpace(m[1])
	}

	var out []Match
	idx := make(map[string]int)
	add := func(name, version, evidence string, weak bool) {
		if i, ok := idx[name]; ok {
			if out[i].Version == "" {
				out[i].Version = version
			}
			return
		}
		idx[name] = len(out)
		out = append(out, Match{
			Name:     name,
			Version:  version,
			Evidence: evidence,
			Weak:     weak,
			CVEs:     ComponentCVEs(name),
		})
	}

	for i := range rules {
		r := &rules[i]
		if r.Shiro {
			if hasShiroDeleteMe(header) {
				add(r.Name, "", "cookie: rememberMe=deleteMe", r.Weak)
			}
			continue
		}
		if r.Path != "" && !pathMatches(r.Path, path) {
			continue
		}
		tok, ok := r.match(p)
		if !ok {
			continue
		}
		add(r.Name, r.version(p), tok, r.Weak)
	}
	return out
}

// Merge combines observed matches into the fingerprint. Existing components
// keep their richer version/evidence; only new component names are appended.
// The newly added matches are returned so callers can run their exploits again.
func (r *Result) Merge(matches []Match) []Match {
	if r == nil {
		return nil
	}
	idx := make(map[string]int, len(r.Matches))
	for i, m := range r.Matches {
		idx[m.Name] = i
	}
	var added []Match
	for _, m := range matches {
		if i, ok := idx[m.Name]; ok {
			if r.Matches[i].Version == "" {
				r.Matches[i].Version = m.Version
			}
			if r.Matches[i].Evidence == "" {
				r.Matches[i].Evidence = m.Evidence
			}
			continue
		}
		idx[m.Name] = len(r.Matches)
		r.Matches = append(r.Matches, m)
		added = append(added, m)
	}
	return added
}

func hasShiroDeleteMe(h http.Header) bool {
	for _, ck := range h.Values("Set-Cookie") {
		l := strings.ToLower(ck)
		if strings.Contains(l, "rememberme") && strings.Contains(l, "deleteme") {
			return true
		}
	}
	return false
}

// pathMatches reports whether a request path is covered by a path-bound rule.
// Trailing-slash rules also cover their sub-paths; the rule's body/title
// criteria still have to match, so prefix matching cannot create a fingerprint
// on its own.
func pathMatches(rulePath, path string) bool {
	if path == "" {
		path = "/"
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	rp := strings.TrimSuffix(rulePath, "/")
	if rp == "" {
		return true
	}
	return path == rp || strings.HasPrefix(path, rp+"/")
}
