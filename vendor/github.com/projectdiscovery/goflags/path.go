package goflags

import (
	"os"
	"path/filepath"
	"strings"
)

// GetConfigFilePath returns the default config file path
func GetConfigFilePath() (string, error) {
	appName := filepath.Base(os.Args[0])
	// trim extension from app name
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	homePath, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homePath, ".config", appName, "config.yaml"), nil
}
