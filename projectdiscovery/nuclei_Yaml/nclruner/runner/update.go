package runner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blang/semver"
	"github.com/google/go-github/github"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/folderutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei-updatecheck-api/client"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"

	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
)

const (
	userName             = "projectdiscovery"
	repoName             = "nuclei-templates"
	nucleiIgnoreFile     = ".nuclei-ignore"
	nucleiConfigFilename = ".templates-config.json"
)

var reVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

// updateTemplates checks if the default list of nuclei-templates
// exist in the user's home directory, if not the latest revision
// is downloaded from GitHub.
//
// If the path exists but does not contain the latest version of public templates,
// the new version is downloaded from GitHub to the templates' directory, overwriting the old content.
func (r *Runner) updateTemplates() error { // TODO this method does more than just update templates. Should be refactored.
	configDir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	_ = os.MkdirAll(configDir, 0755)

	if err := r.readInternalConfigurationFile(configDir); err != nil {
		return errors.Wrap(err, "could not read configuration file")
	}

	// If the config doesn't exist, create it now.
	defaultTemplatesDirectory, err := utils.GetDefaultTemplatePath()
	if err != nil {
		return err
	}
	if r.templatesConfig == nil {
		currentConfig := &config.Config{
			TemplatesDirectory: defaultTemplatesDirectory,
			NucleiVersion:      config.Version,
		}
		if writeErr := config.WriteConfiguration(currentConfig); writeErr != nil {
			return errors.Wrap(writeErr, "could not write template configuration")
		}
		r.templatesConfig = currentConfig
	}
	if r.options.TemplatesDirectory == "" {
		if r.templatesConfig.TemplatesDirectory != "" {
			r.options.TemplatesDirectory = r.templatesConfig.TemplatesDirectory
		} else {
			r.options.TemplatesDirectory = defaultTemplatesDirectory
		}
	}

	if r.options.NoUpdateTemplates && !r.options.UpdateTemplates {
		return nil
	}

	client.InitNucleiVersion(config.Version)
	r.fetchLatestVersionsFromGithub(configDir) // also fetch the latest versions

	ctx := context.Background()

	var noTemplatesFound bool
	if !fileutil.FolderExists(r.templatesConfig.TemplatesDirectory) {
		noTemplatesFound = true
	}

	if r.templatesConfig.TemplateVersion == "" || (r.options.TemplatesDirectory != "" && r.templatesConfig.TemplatesDirectory != r.options.TemplatesDirectory) || noTemplatesFound {
		gologger.Info().Msgf("nuclei-templates are not installed, installing...\n")

		if r.options.TemplatesDirectory != "" && r.templatesConfig.TemplatesDirectory != r.options.TemplatesDirectory {
			r.templatesConfig.TemplatesDirectory, _ = filepath.Abs(r.options.TemplatesDirectory)
		}
		r.fetchLatestVersionsFromGithub(configDir) // also fetch the latest versions

		version, err := semver.Parse(r.templatesConfig.NucleiTemplatesLatestVersion)
		if err != nil {
			return err
		}

		// Download the repository and write the revision to a HEAD file.
		asset, getErr := r.getLatestReleaseFromGithub(r.templatesConfig.NucleiTemplatesLatestVersion)
		if getErr != nil {
			return getErr
		}
		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", version.String(), r.templatesConfig.TemplatesDirectory)

		if _, err := r.downloadReleaseAndUnzip(ctx, version.String(), asset.GetZipballURL()); err != nil {
			return err
		}
		r.templatesConfig.TemplateVersion = version.String()

		if err := config.WriteConfiguration(r.templatesConfig); err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully downloaded nuclei-templates (v%s) to %s. GoodLuck!\n", version.String(), r.templatesConfig.TemplatesDirectory)
		return nil
	}

	latestVersion, currentVersion, err := getVersions(r)
	if err != nil {
		return err
	}

	if latestVersion.EQ(currentVersion) {
		if r.options.UpdateTemplates {
			gologger.Info().Msgf("No new updates found for nuclei templates")
		}
		return config.WriteConfiguration(r.templatesConfig)
	}

	if err := r.updateTemplatesWithVersion(latestVersion, currentVersion, r, ctx); err != nil {
		return err
	}
	return nil
}

func (r *Runner) updateTemplatesWithVersion(latestVersion semver.Version, currentVersion semver.Version, runner *Runner, ctx context.Context) error {
	if latestVersion.GT(currentVersion) {
		gologger.Info().Msgf("Your current nuclei-templates v%s are outdated. Latest is v%s\n", currentVersion, latestVersion.String())
		gologger.Info().Msgf("Downloading latest release...")

		if runner.options.TemplatesDirectory != "" {
			runner.templatesConfig.TemplatesDirectory = runner.options.TemplatesDirectory
		}
		runner.templatesConfig.TemplateVersion = latestVersion.String()

		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", latestVersion.String(), runner.templatesConfig.TemplatesDirectory)

		asset, err := runner.getLatestReleaseFromGithub(runner.templatesConfig.NucleiTemplatesLatestVersion)
		if err != nil {
			return err
		}
		if _, err := runner.downloadReleaseAndUnzip(ctx, latestVersion.String(), asset.GetZipballURL()); err != nil {
			return err
		}
		if err := config.WriteConfiguration(runner.templatesConfig); err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully updated nuclei-templates (v%s) to %s. GoodLuck!\n", latestVersion.String(), r.templatesConfig.TemplatesDirectory)
	}
	return nil
}

func getVersions(runner *Runner) (semver.Version, semver.Version, error) {
	// Get the configuration currently on disk.
	verText := runner.templatesConfig.TemplateVersion
	indices := reVersion.FindStringIndex(verText)
	if indices == nil {
		return semver.Version{}, semver.Version{}, fmt.Errorf("invalid release found with tag %s", verText)
	}
	if indices[0] > 0 {
		verText = verText[indices[0]:]
	}

	currentVersion, err := semver.Make(verText)
	if err != nil {
		return semver.Version{}, semver.Version{}, err
	}

	latestVersion, err := semver.Parse(runner.templatesConfig.NucleiTemplatesLatestVersion)
	if err != nil {
		return semver.Version{}, semver.Version{}, err
	}
	return latestVersion, currentVersion, nil
}

// readInternalConfigurationFile reads the nclruner configuration file for nuclei
func (r *Runner) readInternalConfigurationFile(configDir string) error {
	templatesConfigFile := filepath.Join(configDir, nucleiConfigFilename)
	if _, statErr := os.Stat(templatesConfigFile); !os.IsNotExist(statErr) {
		configuration, readErr := config.ReadConfiguration()
		if readErr != nil {
			return readErr
		}
		r.templatesConfig = configuration
	}
	return nil
}

// checkNucleiIgnoreFileUpdates checks .nuclei-ignore file for updates from GitHub
func (r *Runner) checkNucleiIgnoreFileUpdates(configDir string) bool {
	data, err := client.GetLatestIgnoreFile()
	if err != nil {
		return false
	}
	if len(data) > 0 {
		_ = ioutil.WriteFile(filepath.Join(configDir, nucleiIgnoreFile), data, 0644)
	}
	if r.templatesConfig != nil {
		if err := config.WriteConfiguration(r.templatesConfig); err != nil {
			gologger.Warning().Msgf("Could not get ignore-file from server: %s", err)
		}
	}
	return true
}

func getGHClientIncognito() *github.Client {
	var tc *http.Client
	return github.NewClient(tc)
}

func getGHClientWithToken() *github.Client {
	if token, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		oauthClient := oauth2.NewClient(ctx, ts)
		return github.NewClient(oauthClient)
	}
	return nil
}

// getLatestReleaseFromGithub returns the latest release from GitHub
func (r *Runner) getLatestReleaseFromGithub(latestTag string) (*github.RepositoryRelease, error) {
	var (
		gitHubClient *github.Client
		retried      bool
	)
	gitHubClient = getGHClientIncognito()
getRelease:
	release, _, err := gitHubClient.Repositories.GetReleaseByTag(context.Background(), userName, repoName, "v"+latestTag)
	if err != nil {
		// retry with authentication
		if gitHubClient = getGHClientWithToken(); gitHubClient != nil && !retried {
			retried = true
			goto getRelease
		}
		return nil, err
	}
	if release == nil {
		return nil, errors.New("no version found for the templates")
	}
	return release, nil
}

// downloadReleaseAndUnzip downloads and unzips the release in a directory
func (r *Runner) downloadReleaseAndUnzip(ctx context.Context, version, downloadURL string) (*templateUpdateResults, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request to %s: %w", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download a release file from %s: %w", downloadURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create buffer for zip file: %w", err)
	}

	reader := bytes.NewReader(buf)
	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress zip file: %w", err)
	}

	// Create the template folder if it doesn't exist
	if err := os.MkdirAll(r.templatesConfig.TemplatesDirectory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create template base folder: %w", err)
	}

	results, err := r.compareAndWriteTemplates(zipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to write templates: %w", err)
	}

	if r.options.Verbose {
		r.printUpdateChangelog(results, version)
	}
	checksumFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".checksum")
	if err := writeTemplatesChecksum(checksumFile, results.checksums); err != nil {
		return nil, errors.Wrap(err, "could not write checksum")
	}

	return results, err
}

type templateUpdateResults struct {
	additions     []string
	deletions     []string
	modifications []string
	totalCount    int
	checksums     map[string]string
}

// compareAndWriteTemplates compares and returns the stats of a template update operations.
func (r *Runner) compareAndWriteTemplates(zipReader *zip.Reader) (*templateUpdateResults, error) {
	results := &templateUpdateResults{
		checksums: make(map[string]string),
	}

	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	configuredTemplateDirectory := r.templatesConfig.TemplatesDirectory
	checksumFile := filepath.Join(configuredTemplateDirectory, ".checksum")
	templateChecksumsMap, _ := createTemplateChecksumsMap(checksumFile)
	for _, zipTemplateFile := range zipReader.File {
		templateAbsolutePath, skipFile, err := calculateTemplateAbsolutePath(zipTemplateFile.Name, configuredTemplateDirectory)
		if err != nil {
			return nil, err
		}
		if skipFile {
			continue
		}

		newTemplateChecksum, err := writeUnZippedTemplateFile(templateAbsolutePath, zipTemplateFile)
		if err != nil {
			return nil, err
		}

		oldTemplateChecksum, checksumOk := templateChecksumsMap[templateAbsolutePath]

		relativeTemplatePath, err := filepath.Rel(configuredTemplateDirectory, templateAbsolutePath)
		if err != nil {
			return nil, fmt.Errorf("could not calculate relative path for template: %s. %w", templateAbsolutePath, err)
		}

		if checksumOk && oldTemplateChecksum[0] != newTemplateChecksum {
			results.modifications = append(results.modifications, relativeTemplatePath)
		}
		results.checksums[templateAbsolutePath] = newTemplateChecksum
		results.totalCount++
	}

	var err error
	results.additions, err = r.readNewTemplatesFile()
	if err != nil {
		results.additions = []string{}
	}

	// If we don't find the previous file in the newly downloaded list,
	// and it hasn't been changed on the disk, delete it.
	for templatePath, templateChecksums := range templateChecksumsMap {
		_, ok := results.checksums[templatePath]
		if !ok && templateChecksums[0] == templateChecksums[1] {
			_ = os.Remove(templatePath)
			results.deletions = append(results.deletions, strings.TrimPrefix(strings.TrimPrefix(templatePath, configuredTemplateDirectory), string(os.PathSeparator)))
		}
	}
	return results, nil
}

func writeUnZippedTemplateFile(templateAbsolutePath string, zipTemplateFile *zip.File) (string, error) {
	if "" == templateAbsolutePath {
		return "", fmt.Errorf("templateAbsolutePath not is nil")
	}
	templateFile, err := os.OpenFile(templateAbsolutePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("could not create template file: %w", err)
	}

	zipTemplateFileReader, err := zipTemplateFile.Open()
	if err != nil {
		_ = templateFile.Close()
		return "", fmt.Errorf("could not open archive to extract file: %w", err)
	}

	md5Hash := md5.New()

	// Save file and also read into hash.Hash for md5
	if _, err := io.Copy(templateFile, io.TeeReader(zipTemplateFileReader, md5Hash)); err != nil {
		_ = templateFile.Close()
		return "", fmt.Errorf("could not write template file: %w", err)
	}

	if err := templateFile.Close(); err != nil {
		return "", fmt.Errorf("could not close file newly created template file: %w", err)
	}

	checksum := hex.EncodeToString(md5Hash.Sum(nil))
	return checksum, nil
}

func calculateTemplateAbsolutePath(zipFilePath, configuredTemplateDirectory string) (string, bool, error) {
	directory, fileName := filepath.Split(zipFilePath)

	if !strings.EqualFold(fileName, ".new-additions") {
		if strings.TrimSpace(fileName) == "" || strings.HasPrefix(fileName, ".") || strings.EqualFold(fileName, "README_CN.md") {
			return "", true, nil
		}
	}

	var (
		directoryPathChunks                 []string
		relativeDirectoryPathWithoutZipRoot string
	)
	if folderutil.IsUnixOS() {
		directoryPathChunks = strings.Split(directory, string(os.PathSeparator))
	} else if folderutil.IsWindowsOS() {
		pathInfo, _ := folderutil.NewPathInfo(directory)
		directoryPathChunks = pathInfo.Parts
	}
	relativeDirectoryPathWithoutZipRoot = filepath.Join(directoryPathChunks[1:]...)

	if strings.HasPrefix(relativeDirectoryPathWithoutZipRoot, ".") {
		return "", true, nil
	}

	templateDirectory := filepath.Join(configuredTemplateDirectory, relativeDirectoryPathWithoutZipRoot)

	if err := os.MkdirAll(templateDirectory, 0755); err != nil {
		return "", false, fmt.Errorf("failed to create template folder: %s. %w", templateDirectory, err)
	}

	return filepath.Join(templateDirectory, fileName), false, nil
}

// createTemplateChecksumsMap reads the previous checksum file from the disk.
// Creates a map of template paths and their previous and currently calculated checksums as values.
func createTemplateChecksumsMap(checksumsFilePath string) (map[string][2]string, error) {
	checksumFile, err := os.Open(checksumsFilePath)
	if err != nil {
		return nil, err
	}
	defer checksumFile.Close()
	scanner := bufio.NewScanner(checksumFile)

	templatePathChecksumsMap := make(map[string][2]string)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		parts := strings.Split(text, ",")
		if len(parts) < 2 {
			continue
		}
		templatePath := parts[0]
		expectedTemplateChecksum := parts[1]

		templateFile, err := os.Open(templatePath)
		if err != nil {
			return nil, err
		}

		hasher := md5.New()
		if _, err := io.Copy(hasher, templateFile); err != nil {
			return nil, err
		}
		templateFile.Close()

		values := [2]string{expectedTemplateChecksum}
		values[1] = hex.EncodeToString(hasher.Sum(nil))
		templatePathChecksumsMap[templatePath] = values
	}
	return templatePathChecksumsMap, nil
}

// writeTemplatesChecksum writes the nuclei-templates checksum data to disk.
func writeTemplatesChecksum(file string, checksum map[string]string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	builder := &strings.Builder{}
	for k, v := range checksum {
		builder.WriteString(k)
		builder.WriteString(",")
		builder.WriteString(v)
		builder.WriteString("\n")

		if _, checksumErr := f.WriteString(builder.String()); checksumErr != nil {
			return err
		}
		builder.Reset()
	}
	return nil
}

func (r *Runner) printUpdateChangelog(results *templateUpdateResults, version string) {
	if len(results.additions) > 0 && r.options.Verbose {
		gologger.Print().Msgf("\nNewly added templates: \n\n")

		for _, addition := range results.additions {
			gologger.Print().Msgf("%s", addition)
		}
	}

	gologger.Print().Msgf("\nNuclei Templates v%s Changelog\n", version)
	data := [][]string{
		{strconv.Itoa(results.totalCount), strconv.Itoa(len(results.additions)), strconv.Itoa(len(results.deletions))},
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Total", "Added", "Removed"})
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}

// fetchLatestVersionsFromGithub fetches the latest versions of nuclei repos from GitHub
//
// This fetches the latest nuclei/templates/ignore from https://version-check.nuclei.sh/versions
// If you want to disable this automatic update check, use -nut flag.
func (r *Runner) fetchLatestVersionsFromGithub(configDir string) {
	versions, err := client.GetLatestNucleiTemplatesVersion()
	if err != nil {
		gologger.Warning().Msgf("Could not fetch latest releases: %s", err)
		return
	}
	if r.templatesConfig != nil {
		r.templatesConfig.NucleiLatestVersion = versions.Nuclei
		r.templatesConfig.NucleiTemplatesLatestVersion = versions.Templates

		// If the fetch has resulted in new version of ignore file, update.
		if r.templatesConfig.NucleiIgnoreHash == "" || r.templatesConfig.NucleiIgnoreHash != versions.IgnoreHash {
			r.templatesConfig.NucleiIgnoreHash = versions.IgnoreHash
			r.checkNucleiIgnoreFileUpdates(configDir)
		}
	}
}

// updateNucleiVersionToLatest implements nuclei auto-update using GitHub Releases.
func updateNucleiVersionToLatest(verbose bool) error {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	var command string
	switch runtime.GOOS {
	case "windows":
		command = "nuclei.exe"
	default:
		command = "nuclei"
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   "projectdiscovery",
			Repo:    "nuclei",
			Version: config.Version,
		},
	}
	releases, err := m.LatestReleases()
	if err != nil {
		return errors.Wrap(err, "could not fetch latest release")
	}
	if len(releases) == 0 {
		gologger.Info().Msgf("No new updates found for nuclei engine!")
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
	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return errors.Wrap(err, "could not download latest release")
	}
	if err := m.Install(tarball); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}
	gologger.Info().Msgf("Successfully updated to Nuclei %s\n", latest.Version)
	return nil
}
