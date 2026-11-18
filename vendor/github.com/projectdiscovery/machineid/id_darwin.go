//go:build darwin
// +build darwin

package machineid

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// machineID returns the uuid returned by `ioreg -rd1 -c IOPlatformExpertDevice`.
// If there is an error running the commad an empty string is returned.
func machineID() (string, error) {
	return IoregValue("IOPlatformUUID")
}

func IoregValue(key string) (string, error) {
	buf, err := RunIoreg()
	if err != nil {
		return "", err
	}
	id, err := extractID(buf.String(), key)
	if err != nil {
		return "", err
	}
	return trim(id), nil
}

func extractID(lines, key string) (string, error) {
	for _, line := range strings.Split(lines, "\n") {
		if strings.Contains(line, key) {
			parts := strings.SplitAfter(line, `" = "`)
			if len(parts) == 2 {
				return strings.TrimRight(parts[1], `"`), nil
			}
		}
	}
	return "", fmt.Errorf("Failed to extract 'IOPlatformUUID' value from `ioreg` output.\n%s", lines)
}

func RunIoreg() (buf *bytes.Buffer, err error) {
	buf, err = runIoreg(false)
	if err == nil {
		return buf, err
	}
	// cron jobs run with a very minimal environment, including a very basic PATH.
	// ioreg is in /usr/sbin, so it won't be found as a command based on that basic PATH
	// let's try to use absolute path
	return runIoreg(true)
}

func runIoreg(tryAbsolutePath bool) (buf *bytes.Buffer, err error) {
	buf = &bytes.Buffer{}
	cmd := "ioreg"
	if tryAbsolutePath {
		cmd = "/usr/sbin/ioreg"
	}
	err = run(buf, os.Stderr, cmd, "-rd1", "-c", "IOPlatformExpertDevice")
	return
}
