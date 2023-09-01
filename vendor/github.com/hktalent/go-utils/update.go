package go_utils

import (
	"fmt"
	"github.com/apex/log"
	"github.com/hktalent/go-update"
	"github.com/hktalent/go-update/progress"
	githubUpdateStore "github.com/hktalent/go-update/stores/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"os/exec"
	"path/filepath"
	"runtime"
)

// 更新到最新版本
func UpdateScan4allVersionToLatest(verbose bool, u, t, dir string) error {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	var command string
	switch runtime.GOOS {
	case "windows":
		command = t + ".exe"
	default:
		command = t
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   u,
			Repo:    t,
			Version: `99.99.99`,
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
	if "" == dir {
		bin, err := exec.LookPath(m.Command)
		if err != nil {
			return errors.Wrapf(err, "looking up path of %q", m.Command)
		}
		dir = filepath.Dir(bin)
	}

	if err := m.InstallTo(tarball, dir); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}
	gologger.Info().Msgf("Successfully updated to %s\n", szLstVer)
	return nil
}
