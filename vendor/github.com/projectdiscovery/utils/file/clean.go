package fileutil

import (
	"os"
	"path/filepath"

	"github.com/projectdiscovery/utils/errkit"
)

var (
	DefaultFilePermission = os.FileMode(0644)
)

// CleanPath cleans paths to migtigate any possible path traversal attacks.
// and it always returns an absolute path
func CleanPath(inputPath string) (string, error) {
	// check if path is abs
	if filepath.IsAbs(inputPath) {
		// clean it using filepath.Abs
		// Abs always calls Clean, so we don't need to call it again
		return filepath.Abs(inputPath)
	}
	// get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// join cwd with inputPath
	joined := filepath.Join(cwd, inputPath)
	// clean it using filepath.Abs
	return filepath.Abs(joined)
}

// CleanPathOrDefault cleans paths to migtigate any possible path traversal attacks.
func CleanPathOrDefault(inputPath string, defaultPath string) string {
	if inputPath == "" {
		return defaultPath
	}
	if val, err := CleanPath(inputPath); err == nil {
		return val
	}
	return defaultPath
}

// ResolveNClean resolves the path and cleans it
// ex: a nuclei template can be either abs or relative to a specified directory
// this function uses given path as a base to resolve the path instead of cwd
func ResolveNClean(inputPath string, baseDir ...string) (string, error) {
	// check if path is abs
	if filepath.IsAbs(inputPath) {
		// clean it using filepath.Abs
		// Abs always calls Clean, so we don't need to call it again
		return filepath.Abs(inputPath)
	}
	for _, dir := range baseDir {
		// join cwd with inputPath
		joined := filepath.Join(dir, inputPath)
		// clean it using filepath.Abs
		abs, err := filepath.Abs(joined)
		if err == nil && FileOrFolderExists(abs) {
			return abs, nil
		}
	}
	return "", errkit.Wrapf(os.ErrNotExist, "failed to resolve path: %s", inputPath)
}

// ResolveNCleanOrDefault resolves the path and cleans it
func ResolveNCleanOrDefault(inputPath string, defaultPath string, baseDir ...string) string {
	if inputPath == "" {
		return defaultPath
	}
	if val, err := ResolveNClean(inputPath, baseDir...); err == nil {
		return val
	}
	return defaultPath
}

// SafeOpen opens a file after cleaning the path
// in read mode
func SafeOpen(path string) (*os.File, error) {
	abs, err := CleanPath(path)
	if err != nil {
		return nil, err
	}
	return os.Open(abs)
}

// SafeOpenAppend opens a file after cleaning the path
// in append mode and creates any missing directories in chain /path/to/file
func SafeOpenAppend(path string) (*os.File, error) {
	abs, err := CleanPath(path)
	if err != nil {
		return nil, err
	}
	_ = FixMissingDirs(abs)
	return os.OpenFile(abs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, DefaultFilePermission)
}

// SafeOpenWrite opens a file after cleaning the path
// in write mode and creates any missing directories in chain /path/to/file
func SafeOpenWrite(path string) (*os.File, error) {
	abs, err := CleanPath(path)
	if err != nil {
		return nil, err
	}
	_ = FixMissingDirs(abs)
	return os.OpenFile(abs, os.O_CREATE|os.O_WRONLY, DefaultFilePermission)
}

// SafeWriteFile writes data to a file after cleaning the path
// in write mode and creates any missing directories in chain /path/to/file
func SafeWriteFile(path string, data []byte) error {
	abs, err := CleanPath(path)
	if err != nil {
		return err
	}
	_ = FixMissingDirs(abs)
	return os.WriteFile(abs, data, DefaultFilePermission)
}

// FixMissingDirs creates any missing directories in chain /path/to/file
func FixMissingDirs(path string) error {
	abs, err := CleanPath(path)
	if err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(abs), os.ModePerm)
}
