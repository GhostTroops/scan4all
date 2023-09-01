package fastdialer

type ContextOption string

const (
	// SniName to use in tls connection
	SniName ContextOption = "sni-name"
	IP      ContextOption = "ip"
)
