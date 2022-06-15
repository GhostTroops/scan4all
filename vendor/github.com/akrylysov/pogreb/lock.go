package pogreb

import (
	"os"

	"github.com/akrylysov/pogreb/fs"
)

const (
	lockName = "lock"
)

func createLockFile(opts *Options) (fs.LockFile, bool, error) {
	return opts.FileSystem.CreateLockFile(lockName, os.FileMode(0644))
}
