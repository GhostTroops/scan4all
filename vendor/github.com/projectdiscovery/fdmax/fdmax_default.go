//go:build !windows

package fdmax

import (
	"bytes"
	"os/exec"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// Get the current limits
func Get() (*Limits, error) {
	var rLimit unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return nil, err
	}

	return &Limits{Current: uint64(rLimit.Cur), Max: uint64(rLimit.Max)}, nil
}

func GetWithUlimit() (*Limits, error) {
	if runtime.GOOS != "darwin" {
		return nil, ErrUnsupportedPlatform
	}
	cmd := exec.Command("ulimit", "-n")
	ulimitCurrent, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	ulimitCurrent = bytes.ReplaceAll(ulimitCurrent, []byte("\n"), []byte(""))
	ulimitCurrentInt, err := strconv.ParseUint(string(ulimitCurrent), 10, 64)
	if err != nil {
		return nil, err
	}
	return &Limits{Current: ulimitCurrentInt, Max: ulimitCurrentInt}, nil
}

func Set(maxLimit uint64) error {
	var rLimit unix.Rlimit
	rLimit.Max = maxLimit
	rLimit.Cur = getMaxLimit(maxLimit)
	return unix.Setrlimit(unix.RLIMIT_NOFILE, &rLimit)
}

func SetWithUlimit(maxLimit uint64) error {
	if runtime.GOOS != "darwin" {
		return ErrUnsupportedPlatform
	}
	maxLimit = getMaxLimit(maxLimit)
	cmd := exec.Command("ulimit", "-n", strconv.FormatUint(maxLimit, 10))
	_, err := cmd.Output()
	return err
}

func getMaxLimit(maxLimit uint64) uint64 {
	if runtime.GOOS == "darwin" && maxLimit > OSXMax {
		return OSXMax
	}
	return maxLimit
}
