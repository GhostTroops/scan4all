package fastdialer

import (
	"context"
	"strings"
)

type ContextOption string

const (
	// SniName to use in tls connection
	SniName ContextOption = "sni-name"
	IP      ContextOption = "ip"
)

// resolveOverrideKey is the context key of the ip a host is pinned to.
type resolveOverrideKey string

// WithResolveOverride returns a copy of ctx in which dials to host connect to
// ip instead of resolving host, like curl --resolve. host is compared with the
// hostname of the dialed address, case-insensitively and on any port, and the
// hostname is still used for SNI. Other hosts dialed with the same context,
// such as redirect targets or a proxy, are resolved as usual.
//
// The IP context option and an ip given in the address (host:port:ip) take
// precedence over an override.
func WithResolveOverride(ctx context.Context, host, ip string) context.Context {
	return context.WithValue(ctx, overrideKey(host), ip)
}

// resolveOverride returns the ip hostname is pinned to in ctx, if any.
func resolveOverride(ctx context.Context, hostname string) string {
	ip, _ := ctx.Value(overrideKey(hostname)).(string)
	return ip
}

func overrideKey(host string) resolveOverrideKey {
	return resolveOverrideKey(strings.TrimSuffix(strings.ToLower(asAscii(host)), "."))
}
