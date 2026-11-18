package goflags

import (
	"os"
	"path/filepath"
	"strings"

	folderutil "github.com/projectdiscovery/utils/folder"
)

var oldAppConfigDir = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", getToolName())

// GetConfigFilePath returns the highest-priority config file path.
func (flagSet *FlagSet) GetConfigFilePath() (string, error) {
	if len(flagSet.configFilePaths) > 0 {
		return flagSet.configFilePaths[len(flagSet.configFilePaths)-1], nil
	}

	return filepath.Join(folderutil.AppConfigDirOrDefault(".", getToolName()), "config.yaml"), nil
}

func (flagSet *FlagSet) getConfigFilePaths() []string {
	if len(flagSet.configFilePaths) > 0 {
		return flagSet.configFilePaths
	}

	return []string{filepath.Join(folderutil.AppConfigDirOrDefault(".", getToolName()), "config.yaml")}
}

// GetToolConfigDir returns the config dir path of the tool
func (flagset *FlagSet) GetToolConfigDir() string {
	cfgFilePath, _ := flagset.GetConfigFilePath()
	return filepath.Dir(cfgFilePath)
}

// SetConfigFilePath sets the only config file path.
func (flagSet *FlagSet) SetConfigFilePath(filePath string) {
	if filePath == "" {
		flagSet.SetConfigFilePaths()
		return
	}

	flagSet.SetConfigFilePaths(filePath)
}

// SetConfigFilePaths sets config file paths from lowest to highest priority.
// Parse ignores missing lower-priority files and creates the last file when it
// does not exist. Command-line flags take precedence over all config files.
func (flagSet *FlagSet) SetConfigFilePaths(filePaths ...string) {
	flagSet.configFilePaths = make([]string, 0, len(filePaths))
	for _, filePath := range filePaths {
		if filePath != "" {
			flagSet.configFilePaths = append(flagSet.configFilePaths, filePath)
		}
	}
}

// getToolName returns the name of the tool
func getToolName() string {
	appName := filepath.Base(os.Args[0])
	return strings.TrimSuffix(appName, filepath.Ext(appName))
}
