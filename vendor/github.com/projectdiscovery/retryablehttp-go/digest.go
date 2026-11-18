package retryablehttp

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"slices"
	"strings"
)

// digestChallenge is a WWW-Authenticate Digest challenge (RFC 7616) that the
// client can answer.
type digestChallenge struct {
	realm, nonce, opaque string
	// algorithm is echoed back as sent; newHash and sess are derived from it.
	algorithm string
	newHash   func() hash.Hash
	sess      bool
	// qop is the chosen quality of protection: "auth", "auth-int", or "" when
	// the server offers none (RFC 2069).
	qop      string
	userhash bool
}

// findDigestChallenge returns the first Digest challenge in h that the client
// supports. A single WWW-Authenticate value can hold several challenges.
func findDigestChallenge(h http.Header) (digestChallenge, bool) {
	for _, v := range h.Values("WWW-Authenticate") {
		for v != "" {
			scheme, params, rest := cutChallenge(v)
			v = rest
			if !strings.EqualFold(scheme, "Digest") {
				continue
			}
			if c, ok := newDigestChallenge(params); ok {
				return c, true
			}
		}
	}
	return digestChallenge{}, false
}

func newDigestChallenge(p map[string]string) (digestChallenge, bool) {
	c := digestChallenge{
		realm:     p["realm"],
		nonce:     p["nonce"],
		opaque:    p["opaque"],
		algorithm: p["algorithm"],
		userhash:  strings.EqualFold(p["userhash"], "true"),
	}
	if c.nonce == "" {
		return digestChallenge{}, false
	}

	var base string
	base, c.sess = strings.CutSuffix(strings.ToUpper(c.algorithm), "-SESS")
	switch base {
	case "", "MD5":
		c.newHash = md5.New
	case "SHA-256":
		c.newHash = sha256.New
	case "SHA-512-256":
		c.newHash = sha512.New512_256
	default:
		return digestChallenge{}, false
	}

	if qop, ok := p["qop"]; ok {
		offered := strings.FieldsFunc(qop, func(r rune) bool { return r == ',' || r == ' ' })
		switch {
		case slices.Contains(offered, "auth"):
			c.qop = "auth"
		case slices.Contains(offered, "auth-int"):
			c.qop = "auth-int"
		default:
			return digestChallenge{}, false
		}
	}
	return c, true
}

// authorization returns the Authorization header value that answers c for a
// request with the given method, request-target uri, and body, using cnonce as
// the client nonce.
func (c digestChallenge) authorization(auth *Auth, method, uri string, body []byte, cnonce string) string {
	h := func(parts ...string) string {
		sum := c.newHash()
		_, _ = io.WriteString(sum, strings.Join(parts, ":"))
		return hex.EncodeToString(sum.Sum(nil))
	}

	ha1 := h(auth.Username, c.realm, auth.Password)
	if c.sess {
		ha1 = h(ha1, c.nonce, cnonce)
	}
	ha2 := h(method, uri)
	if c.qop == "auth-int" {
		ha2 = h(method, uri, h(string(body)))
	}

	username := auth.Username
	if c.userhash {
		username = h(auth.Username, c.realm)
	}
	fields := []string{
		"username=" + quote(username),
		"realm=" + quote(c.realm),
		"nonce=" + quote(c.nonce),
		"uri=" + quote(uri),
	}
	if c.algorithm != "" {
		fields = append(fields, "algorithm="+c.algorithm)
	}
	var response string
	if c.qop == "" {
		response = h(ha1, c.nonce, ha2)
	} else {
		// Each challenge is answered once, so the nonce count is always 1.
		const nc = "00000001"
		response = h(ha1, c.nonce, nc, cnonce, c.qop, ha2)
		fields = append(fields, "qop="+c.qop, "nc="+nc, "cnonce="+quote(cnonce))
	}
	fields = append(fields, "response="+quote(response))
	if c.opaque != "" {
		fields = append(fields, "opaque="+quote(c.opaque))
	}
	if c.userhash {
		fields = append(fields, "userhash=true")
	}
	return "Digest " + strings.Join(fields, ", ")
}

// cutChallenge parses the first challenge in a WWW-Authenticate value, such as
// `Digest realm="r", qop="auth,auth-int"` (RFC 9110, section 11.6.1). It
// returns the auth-scheme, the auth-params keyed by lowercase name, and the
// rest of s, which starts at the next challenge.
func cutChallenge(s string) (scheme string, params map[string]string, rest string) {
	scheme, s = cutToken(strings.TrimLeft(s, ", \t"))
	for {
		s = strings.TrimLeft(s, ", \t")
		name, after := cutToken(s)
		value, ok := strings.CutPrefix(strings.TrimLeft(after, " \t"), "=")
		if !ok {
			// name isn't followed by "=", so it starts the next challenge.
			// Returning before it keeps parsing linear in len(s).
			return scheme, params, s
		}
		value = strings.TrimLeft(value, " \t")
		if quoted, ok := strings.CutPrefix(value, `"`); ok {
			value, s = cutQuotedString(quoted)
		} else {
			value, s, _ = strings.Cut(value, ",")
			value = strings.TrimSpace(value)
		}
		if params == nil {
			params = make(map[string]string)
		}
		params[strings.ToLower(name)] = value
	}
}

// cutToken splits s before its first comma, space, tab, or equals sign.
func cutToken(s string) (token, rest string) {
	if i := strings.IndexAny(s, ", \t="); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// cutQuotedString unescapes s up to its closing quote, and returns the result
// and the rest of s after that quote. The opening quote must already be
// removed.
func cutQuotedString(s string) (value, rest string) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return b.String(), s[i+1:]
		}
		if c == '\\' && i+1 < len(s) {
			i++
			c = s[i]
		}
		b.WriteByte(c)
	}
	return b.String(), ""
}

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// quote returns s as an HTTP quoted-string.
func quote(s string) string {
	return `"` + quoteEscaper.Replace(s) + `"`
}
