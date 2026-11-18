package updateutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/uuid"
	"github.com/logrusorgru/aurora/v4"

	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/projectdiscovery/utils/process"
)

type AssetFormat uint

const (
	Zip AssetFormat = iota
	Tar
	Unknown
)

// FileExtension of this asset format
func (a AssetFormat) FileExtension() string {
	switch a {
	case Zip:
		return ".zip"
	case Tar:
		return ".tar.gz"
	default:
		return ""
	}
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
var Aurora = aurora.New(aurora.WithColors(true))

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
	return currentVer.LessThan(latestVer)
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

// getUtmSource returns utm_source from environment variable or "unknown" value
// this is non-intrusive way to identify the source of the tool to improve tool experience across environments
func getUtmSource() string {
	value := "unknown"
	switch {
	case os.Getenv("GH_ACTION") != "":
		value = "ghci"
	case os.Getenv("TRAVIS") != "":
		value = "travis"
	case os.Getenv("CIRCLECI") != "":
		value = "circleci"
	case os.Getenv("CI") != "":
		value = "gitlabci" // this also includes bitbucket
	case os.Getenv("GITHUB_ACTIONS") != "":
		value = "ghci"
	case os.Getenv("AWS_EXECUTION_ENV") != "":
		value = os.Getenv("AWS_EXECUTION_ENV")
	case os.Getenv("JENKINS_URL") != "":
		value = "jenkins"
	case os.Getenv("FUNCTION_TARGET") != "":
		value = "gcf"
	case os.Getenv("GOOGLE_CLOUD_PROJECT") != "":
		value = "gcp"
	case os.Getenv("HEROKU_APP_NAME") != "":
		value = "heroku"
	case os.Getenv("DYNO") != "":
		value = "heroku"
	case os.Getenv("ECS_CONTAINER_METADATA_URI") != "":
		value = "ecs"
	case os.Getenv("EC2_INSTANCE_ID") != "":
		value = "ec2"
	case os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		value = "k8s"
	case os.Getenv("KUBERNETES_PORT") != "":
		value = "k8s"
	case os.Getenv("AZURE_FUNCTIONS_ENVIRONMENT") != "":
		value = "azure"
	case os.Getenv("__OW_API_HOST") != "":
		value = "ibmcf"
	case os.Getenv("OCI_RESOURCE_PRINCIPAL_VERSION") != "":
		value = "oracle"
	case os.Getenv("GAE_RUNTIME") != "":
		value = os.Getenv("GAE_RUNTIME")
	default:
		if ok, val := process.RunningInContainer(); ok {
			return val
		}
	}
	if value == "" {
		value = "unknown"
	}
	return value
}

// getCustomMID returns a unique identifier that is unique to the machine
// this might be used for rate limiting
func getCustomMID() string {
	dir := folderutil.AppConfigDirOrDefault(os.TempDir(), "subfinder")
	if !fileutil.FolderExists(dir) {
		_ = fileutil.CreateFolders(dir)
	}
	midFile := filepath.Join(dir, "uuid.txt")
	if !fileutil.FileExists(midFile) {
		uuid := uuid.New()
		_ = os.WriteFile(midFile, []byte(uuid.String()), 0600)
	}
	bin, _ := os.ReadFile(midFile)
	mid := string(bin)
	if mid == "" {
		mid = "error"
	}
	return mid
}
