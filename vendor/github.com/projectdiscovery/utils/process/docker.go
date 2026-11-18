package process

import (
	"bufio"
	"os"
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
)

// RunningInContainer checks if the process is running in a docker container
// and returns true if it is.
// reference: https://www.baeldung.com/linux/is-process-running-inside-container
func RunningInContainer() (bool, string) {
	if fileutil.FileOrFolderExists("/.dockerenv") {
		return true, "docker"
	}
	// fallback and check using controlgroup 1 detect
	if !fileutil.FileExists("/proc/1/cgroup") {
		return false, ""
	}
	f, err := os.Open("/proc/1/cgroup")
	if err != nil {
		return false, ""
	}
	defer func() {
		_ = f.Close()
	}()
	buff := bufio.NewScanner(f)
	for buff.Scan() {
		if strings.Contains(buff.Text(), "/docker") {
			return true, "docker"
		}
		if strings.Contains(buff.Text(), "/lxc") {
			return true, "lxc"
		}
	}
	// fallback and check using controlgroup 2 detect
	f2, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, ""
	}
	defer func() {
		_ = f2.Close()
	}()
	buff2 := bufio.NewScanner(f2)
	for buff2.Scan() {
		if strings.Contains(buff2.Text(), "/docker") {
			return true, "docker"
		}
		if strings.Contains(buff2.Text(), "/lxc") {
			return true, "lxc"
		}
	}

	return false, ""
}
