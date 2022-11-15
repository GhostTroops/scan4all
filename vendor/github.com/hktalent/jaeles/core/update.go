package core

import (
	"fmt"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"os"
	"path"
)

// UpdatePlugins update latest UI and Plugins from default repo
func UpdatePlugins(options libs.Options) {
	pluginPath := path.Join(options.RootFolder, "plugins")
	url := libs.UIREPO
	utils.GoodF("Cloning Plugins from: %v", url)
	if utils.FolderExists(pluginPath) {
		utils.InforF("Remove: %v", pluginPath)
		os.RemoveAll(pluginPath)
	}
	_, err := git.PlainClone(pluginPath, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
		Depth:             1,
	})

	if err != nil {
		utils.ErrorF("Error to clone Plugins repo: %v - %v", url, err)
		return
	}
}

// UpdateSignature update latest UI from UI repo
func UpdateSignature(options libs.Options) {
	signPath := path.Join(options.RootFolder, "base-signatures")
	url := libs.SIGNREPO
	// in case we want to in private repo
	if options.Config.Repo != "" {
		url = options.Config.Repo
	}

	utils.GoodF("Cloning Signature from: %v", url)
	if utils.FolderExists(signPath) {
		utils.InforF("Remove: %v", signPath)
		os.RemoveAll(signPath)
		os.RemoveAll(options.PassiveFolder)
		os.RemoveAll(options.ResourcesFolder)
		os.RemoveAll(options.ThirdPartyFolder)
	}
	if options.Config.PrivateKey != "" {
		cmd := fmt.Sprintf("GIT_SSH_COMMAND='ssh -o StrictHostKeyChecking=no -i %v' git clone --depth=1 %v %v", options.Config.PrivateKey, url, signPath)
		Execution(cmd)
	} else {
		var err error
		if options.Server.Username != "" && options.Server.Password != "" {
			_, err = git.PlainClone(signPath, false, &git.CloneOptions{
				Auth: &http.BasicAuth{
					Username: options.Config.Username,
					Password: options.Config.Password,
				},
				URL:               url,
				RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
				Depth:             1,
				Progress:          os.Stdout,
			})
		} else {
			_, err = git.PlainClone(signPath, false, &git.CloneOptions{
				URL:               url,
				RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
				Depth:             1,
				Progress:          os.Stdout,
			})
		}

		if err != nil {
			utils.ErrorF("Error to clone Signature repo: %v - %v", url, err)
			return
		}
	}
}
