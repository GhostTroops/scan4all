package bugbounty

import (
	"strings"

	"github.com/GhostTroops/scan4all/pkg/cvecore/exploit"
)

// CVE-2026-4631 Cockpit 326–359 SSH argument injection (pre-auth RCE).
func ProbeCockpit(base string) *Finding {
	out := exploit.CVE20264631(base, "id")
	if out == "" || !strings.Contains(out, "uid=") {
		return nil
	}
	return &Finding{Target: base, Vuln: "CVE-2026-4631 Cockpit SSH Argument Injection RCE", Severity: "CRITICAL",
		Detail: "id: " + out, URL: base + "/cockpit/login"}
}
