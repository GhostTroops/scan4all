package updateutils

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/logrusorgru/aurora"
)

type AssetFormat uint

const (
	Zip AssetFormat = iota
	Tar
	Unknown
)

// FileExtension of this asset format
func (a AssetFormat) FileExtension() string {
	if a == Zip {
		return ".zip"
	} else if a == Tar {
		return ".tar.gz"
	}
	return ""
}

func IdentifyAssetFormat(assetName string) AssetFormat {
	switch {
	case strings.HasSuffix(assetName, Zip.FileExtension()):
		return Zip
	case strings.HasSuffix(assetName, Tar.FileExtension()):
		return Tar
	default:
		return Unknown
	}
}

// Tool
type Tool struct {
	Name    string            `json:"name"`
	Repo    string            `json:"repo"`
	Version string            `json:"version"`
	Assets  map[string]string `json:"assets"`
}

// Aurora instance
var Aurora aurora.Aurora = aurora.NewAurora(true)

// GetVersionDescription returns tags like (latest) or (outdated) or (dev)
func GetVersionDescription(current string, latest string) string {
	if strings.HasSuffix(current, "-dev") {
		if IsDevReleaseOutdated(current, latest) {
			return fmt.Sprintf("(%v)", Aurora.BrightRed("outdated"))
		} else {
			return fmt.Sprintf("(%v)", Aurora.Blue("development"))
		}
	}
	if IsOutdated(current, latest) {
		return fmt.Sprintf("(%v)", Aurora.BrightRed("outdated"))
	} else {
		return fmt.Sprintf("(%v)", Aurora.BrightGreen("latest"))
	}
}

// IsOutdated returns true if current version is outdated
func IsOutdated(current, latest string) bool {
	if strings.HasSuffix(current, "-dev") {
		return IsDevReleaseOutdated(current, latest)
	}
	currentVer, _ := semver.NewVersion(current)
	latestVer, _ := semver.NewVersion(latest)
	if currentVer == nil || latestVer == nil {
		// fallback to naive comparison
		return current != latest
	}
	return latestVer.GreaterThan(currentVer)
}

// IsDevReleaseOutdated returns true if installed tool (dev version) is outdated
// ex: if installed tools is v2.9.1-dev and latest release is v2.9.1 then it is outdated
// since v2.9.1-dev is released and merged into main/master branch
func IsDevReleaseOutdated(current string, latest string) bool {
	// remove -dev suffix
	current = strings.TrimSuffix(current, "-dev")
	currentVer, _ := semver.NewVersion(current)
	latestVer, _ := semver.NewVersion(latest)
	if currentVer == nil || latestVer == nil {
		if current == latest {
			return true
		} else {
			// can't compare, so consider it latest
			return false
		}
	}
	if latestVer.GreaterThan(currentVer) || latestVer.Equal(currentVer) {
		return true
	}
	return false
}
