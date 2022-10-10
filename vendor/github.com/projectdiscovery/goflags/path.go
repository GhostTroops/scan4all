package goflags

import (
	"os"
	"path/filepath"
	"strings"
)

// GetConfigFilePath returns the config file path
func (flagSet *FlagSet) GetConfigFilePath() (string, error) {
	// return configFilePath if already set
	if flagSet.configFilePath != "" {
		return flagSet.configFilePath, nil
	}
	// generate default config name
	appName := filepath.Base(os.Args[0])
	// trim extension from app name
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	homePath, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homePath, ".config", appName, "config.yaml"), nil
}

// SetConfigFilePath sets custom config file path
func (flagSet *FlagSet) SetConfigFilePath(filePath string) {
	flagSet.configFilePath = filePath
}

// Deprecated: Use FlagSet.GetConfigFilePath instead.
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
