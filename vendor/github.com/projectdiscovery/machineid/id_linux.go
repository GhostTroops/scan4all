//go:build linux
// +build linux

package machineid

import "os"

const (
	// dbusPath is the default path for dbus machine id.
	dbusPath = "/var/lib/dbus/machine-id"
	// dbusPathEtc is the default path for dbus machine id located in /etc.
	// Some systems (like Fedora 20) only know this path.
	// Sometimes it's the other way round.
	dbusPathEtc = "/etc/machine-id"

	// Some old release haven't above two paths.
	// Workaround.
	productPath = "/sys/class/dmi/id/product_uuid"
)

// machineID returns the uuid specified at `/var/lib/dbus/machine-id` or `/etc/machine-id`.
// If there is an error reading the files an empty string is returned.
// See https://unix.stackexchange.com/questions/144812/generate-consistent-machine-unique-id
func machineID() (string, error) {
	id, err := os.ReadFile(dbusPath)
	if err != nil {
		// try fallback path
		id, err = os.ReadFile(dbusPathEtc)
	}
	if err != nil {
		// try fallback path
		id, err = os.ReadFile(productPath)
	}
	if err != nil {
		return "", err
	}
	return trim(string(id)), nil
}
