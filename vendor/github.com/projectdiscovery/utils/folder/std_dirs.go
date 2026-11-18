package folderutil

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

// Below Contains utils for standard directories
// which should be used by tools to store data
// and configuration files respectively

// HomeDirOrDefault tries to obtain the user's home directory and
// returns the default if it cannot be obtained.
func HomeDirOrDefault(defaultDirectory string) string {
	if homeDir, err := os.UserHomeDir(); err == nil && IsWritable(homeDir) {
		return homeDir
	}
	if user, err := user.Current(); err == nil && IsWritable(user.HomeDir) {
		return user.HomeDir
	}
	return defaultDirectory
}

// UserConfigDirOrDefault returns the user config directory or defaultConfigDir in case of error
func UserConfigDirOrDefault(defaultConfigDir string) string {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return defaultConfigDir
	}
	return userConfigDir
}

// AppConfigDirOrDefault returns the app config directory
func AppConfigDirOrDefault(defaultAppConfigDir string, toolName string) string {
	userConfigDir := UserConfigDirOrDefault("")
	if userConfigDir == "" {
		return filepath.Join(defaultAppConfigDir, toolName)
	}
	return filepath.Join(userConfigDir, toolName)
}

// AppCacheDirOrDefault returns the user cache directory or defaultCacheDir in case of error
func AppCacheDirOrDefault(defaultCacheDir string, toolName string) string {
	userCacheDir, err := os.UserCacheDir()
	if err != nil || userCacheDir == "" {
		return filepath.Join(defaultCacheDir, toolName)
	}
	return filepath.Join(userCacheDir, toolName)
}

// Prints the standard directories for a tool
func PrintStdDirs(toolName string) {
	appConfigDir := AppConfigDirOrDefault("", toolName)
	appCacheDir := AppCacheDirOrDefault("", toolName)
	fmt.Printf("[+] %v %-13v: %v\n", toolName, "AppConfigDir", appConfigDir)
	fmt.Printf("[+] %v %-13v: %v\n", toolName, "AppCacheDir", appCacheDir)
}
