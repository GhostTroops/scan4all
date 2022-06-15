package folderutil

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Separator evaluated at runtime
var Separator = string(os.PathSeparator)

const (
	UnixPathSeparator    = "/"
	WindowsPathSeparator = "\\"
)

// GetFiles within a folder
func GetFiles(root string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		matches = append(matches, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// PathInfo about a folder
type PathInfo struct {
	IsAbsolute         bool
	RootPath           string
	Parts              []string
	PartsWithSeparator []string
}

// NewPathInfo returns info about a given path
func NewPathInfo(path string) (PathInfo, error) {
	var pathInfo PathInfo
	path = filepath.Clean(path)
	pathInfo.RootPath = filepath.VolumeName(path)
	if filepath.IsAbs(path) {
		if IsUnixOS() {
			if pathInfo.RootPath == "" {
				pathInfo.IsAbsolute = true
				pathInfo.RootPath = UnixPathSeparator
			}
		} else if IsWindowsOS() {
			pathInfo.IsAbsolute = true
			pathInfo.RootPath = pathInfo.RootPath + WindowsPathSeparator
		}
	}

	pathInfo.Parts = agnosticSplit(path)

	for i, pathItem := range pathInfo.Parts {
		if i == 0 && pathInfo.IsAbsolute {
			if IsUnixOS() {
				pathInfo.PartsWithSeparator = append(pathInfo.PartsWithSeparator, pathInfo.RootPath)
			}
		} else if len(pathInfo.PartsWithSeparator) > 0 && pathInfo.PartsWithSeparator[len(pathInfo.PartsWithSeparator)-1] != Separator {
			pathInfo.PartsWithSeparator = append(pathInfo.PartsWithSeparator, Separator)
		}
		pathInfo.PartsWithSeparator = append(pathInfo.PartsWithSeparator, pathItem)
	}
	return pathInfo, nil
}

// Returns all possible combination of the various levels of the path parts
func (pathInfo PathInfo) Paths() ([]string, error) {
	var combos []string
	for i := 0; i <= len(pathInfo.Parts); i++ {
		var computedPath string
		if pathInfo.IsAbsolute && pathInfo.RootPath != "" {
			// on windows we need to skip the volume, already computed in rootpath
			if IsUnixOS() {
				computedPath = pathInfo.RootPath + filepath.Join(pathInfo.Parts[:i]...)
			} else if IsWindowsOS() && i > 0 {
				skipItems := 0
				if len(pathInfo.Parts) > 0 {
					skipItems = 1
				}
				computedPath = pathInfo.RootPath + filepath.Join(pathInfo.Parts[skipItems:i]...)
			}
		} else {
			computedPath = filepath.Join(pathInfo.Parts[:i]...)
		}
		combos = append(combos, filepath.Clean(computedPath))
	}

	return combos, nil
}

// MeshWith combine all values from Path with another provided path
func (pathInfo PathInfo) MeshWith(anotherPath string) ([]string, error) {
	allPaths, err := pathInfo.Paths()
	if err != nil {
		return nil, err
	}
	var combos []string
	for _, basePath := range allPaths {
		combinedPath := filepath.Join(basePath, anotherPath)
		combos = append(combos, filepath.Clean(combinedPath))
	}

	return combos, nil
}

func IsUnixOS() bool {
	switch runtime.GOOS {
	case "android", "darwin", "freebsd", "ios", "linux", "netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}

func IsWindowsOS() bool {
	return runtime.GOOS == "windows"
}

func agnosticSplit(path string) (parts []string) {
	// split with each known separators
	for _, part := range strings.Split(path, UnixPathSeparator) {
		for _, subPart := range strings.Split(part, WindowsPathSeparator) {
			if part != "" {
				parts = append(parts, subPart)
			}
		}
	}
	return
}

// HomeDirectory
func HomeDirOrDefault(defaultDirectory string) string {
	usr, err := user.Current()
	if err != nil {
		return defaultDirectory
	}
	return usr.HomeDir
}
