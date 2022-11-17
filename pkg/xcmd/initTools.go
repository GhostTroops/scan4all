package xcmd

import (
	"fmt"
	"github.com/apex/log"
	util "github.com/hktalent/go-utils"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"os"
	"runtime"
	"strings"
)

// 更新到最新版本
func UpdateScan4allVersionToLatest(Owner, Repo string, verbose bool) error {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	m := &update.Manager{
		Command: Repo,
		Store: &githubUpdateStore.Store{
			Owner:   Owner,
			Repo:    Repo,
			Version: "999.99.99",
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
	currentOS := GetOsName()
	final := latest.FindZip(currentOS, runtime.GOARCH)
	if final == nil {
		for _, x := range []string{strings.ToUpper(currentOS[0:1]) + currentOS[1:], strings.ToLower(currentOS), runtime.GOOS} {
			final = latest.FindZip(x, runtime.GOARCH)
			if nil != final {
				break
			}
		}

		if nil == final {
			return fmt.Errorf("no compatible binary found for %s %s/%s", Repo, currentOS, runtime.GOARCH)
		}
	}
	//hv := false
	//KvDb1.Get(nil, func(bytes []byte) {
	//	hv = true
	//}, final.URL)
	//if hv {
	//	return fmt.Errorf("Already exists %s %s/%s", Repo, currentOS, runtime.GOARCH)
	//}
	szLstVer := final.Name
	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return errors.Wrap(err, "could not download latest release")
	}
	os.MkdirAll(Pwd+"/tools/"+currentOS, os.ModePerm)
	if err := m.InstallTo(tarball, Pwd+"/tools/"+currentOS+"/"); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}
	KvDb1.Put(final.URL, final)
	gologger.Info().Msgf("Successfully updated to %s\n", szLstVer)
	return nil
}

// 首次运行下载工具包
func InitToolsFile() {
	gologger.Info().Msgf("wait update ... \n")
	if o := util.GetAsAny("update"); nil != o {
		if m1, ok := o.(map[string]interface{}); ok {
			for k, v := range m1 {
				if a1, ok := v.([]interface{}); ok {
					for _, x1 := range a1 {
						func(k1, k2 string) {
							util.DoSyncFunc(func() {
								if err := UpdateScan4allVersionToLatest(k1, k2, true); nil != err {
									log.Debug(err.Error())
								}
							})
						}(k, fmt.Sprintf("%v", x1))
					}
				}
			}
		}
	}
}
