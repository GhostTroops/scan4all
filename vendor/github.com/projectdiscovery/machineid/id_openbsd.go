// +build openbsd

package machineid

import (
	"bytes"
	"os"
)

// If there is an error an empty string is returned.
func machineID() (string, error) {
	buf := &bytes.Buffer{}
	err := run(buf, os.Stderr, "sysctl", "-n", "hw.uuid")
	if err != nil {
		return "", err
	}
	return trim(buf.String()), nil
}
