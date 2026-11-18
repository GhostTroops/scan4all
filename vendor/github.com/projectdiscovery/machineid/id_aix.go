//go:build aix
// +build aix

package machineid

import (
	"bytes"
	"os"
	"strings"
)

// machineID returns the operating system uuid set in the kernel or WPAR uuid if
// applicable.
func machineID() (string, error) {
	buf := &bytes.Buffer{}
	err := run(buf, os.Stderr, "lsattr", "-l", "sys0", "-a", "os_uuid", "-E")
	if err != nil {
		return "", err
	}
	return strings.Split(buf.String(), " ")[1], nil
}
