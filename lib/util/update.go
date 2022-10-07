package util

import (
	"fmt"
	"github.com/apex/log"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"runtime"
)

const Version = `2.7.9`

var MyName = "scan4all"

// 更新到最新版本
func UpdateScan4allVersionToLatest(verbose bool) error {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	var command string
	switch runtime.GOOS {
	case "windows":
		command = MyName + ".exe"
	default:
		command = MyName
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   "hktalent",
			Repo:    "Scan4all_Pro",
			Version: Version,
		},
	}
	releases, err := m.LatestReleases()
	if err != nil {
		return errors.Wrap(err, "could not fetch latest release")
	}
	if len(releases) == 0 {
		gologger.Info().Msgf("No new updates found for scan4all engine!")
		return nil
	}

	latest := releases[0]
	var currentOS string
	switch runtime.GOOS {
	case "darwin":
		currentOS = "macOS"
	default:
		currentOS = runtime.GOOS
	}
	final := latest.FindZip(currentOS, runtime.GOARCH)
	if final == nil {
		return fmt.Errorf("no compatible binary found for %s/%s", currentOS, runtime.GOARCH)
	}
	szLstVer := final.Name
	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return errors.Wrap(err, "could not download latest release")
	}
	if err := m.Install(tarball); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}
	gologger.Info().Msgf("Successfully updated to %s\n", szLstVer)
	return nil
}
