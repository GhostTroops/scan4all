package runner

import (
	"archive/zip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestDownloadReleaseAndUnzipAddition(t *testing.T) {
	gologger.DefaultLogger.SetWriter(&testutils.NoopWriter{})

	templatesDirectory, err := os.MkdirTemp("", "template-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(templatesDirectory)

	r := &Runner{templatesConfig: &config.Config{TemplatesDirectory: templatesDirectory}, options: testutils.DefaultOptions}

	newTempDir, err := os.MkdirTemp("", "new-tmp-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(newTempDir)

	err = os.WriteFile(filepath.Join(newTempDir, "base.yaml"), []byte("id: test"), os.ModePerm)
	require.Nil(t, err, "could not create base file")
	err = os.WriteFile(filepath.Join(newTempDir, "new.yaml"), []byte("id: test"), os.ModePerm)
	require.Nil(t, err, "could not create new file")
	err = os.WriteFile(filepath.Join(newTempDir, ".new-additions"), []byte("new.yaml"), os.ModePerm)
	require.Nil(t, err, "could not create new file")

	err = zipFromDirectory("new.zip", newTempDir)
	require.Nil(t, err, "could not create new zip from directory")
	defer os.Remove("new.zip")

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "new.zip")
	}))
	defer ts2.Close()

	results, err := r.downloadReleaseAndUnzip(context.Background(), "1.0.1", ts2.URL)
	require.Nil(t, err, "could not download release and unzip")

	require.Equal(t, "new.yaml", results.additions[0], "could not get correct new addition")
}

func TestDownloadReleaseAndUnzipDeletion(t *testing.T) {
	gologger.DefaultLogger.SetWriter(&testutils.NoopWriter{})

	baseTemplates, err := os.MkdirTemp("", "old-temp-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(baseTemplates)

	err = os.WriteFile(filepath.Join(baseTemplates, "base.yaml"), []byte("id: test"), os.ModePerm)
	require.Nil(t, err, "could not create write base file")
	err = os.WriteFile(filepath.Join(baseTemplates, ".new-additions"), []byte("base.yaml"), os.ModePerm)
	require.Nil(t, err, "could not create new file")

	err = zipFromDirectory("base.zip", baseTemplates)
	require.Nil(t, err, "could not create zip from directory")
	defer os.Remove("base.zip")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "base.zip")
	}))
	defer ts.Close()

	templatesDirectory, err := os.MkdirTemp("", "template-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(templatesDirectory)

	r := &Runner{templatesConfig: &config.Config{TemplatesDirectory: templatesDirectory}, options: testutils.DefaultOptions}

	results, err := r.downloadReleaseAndUnzip(context.Background(), "1.0.0", ts.URL)
	require.Nil(t, err, "could not download release and unzip")
	require.Equal(t, "base.yaml", results.additions[0], "could not get correct base addition")

	newTempDir, err := os.MkdirTemp("", "new-tmp-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(newTempDir)

	err = os.WriteFile(filepath.Join(newTempDir, ".new-additions"), []byte(""), os.ModePerm)
	require.Nil(t, err, "could not create new file")

	err = zipFromDirectory("new.zip", newTempDir)
	require.Nil(t, err, "could not create new zip from directory")
	defer os.Remove("new.zip")

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "new.zip")
	}))
	defer ts2.Close()

	results, err = r.downloadReleaseAndUnzip(context.Background(), "1.0.1", ts2.URL)
	require.Nil(t, err, "could not download release and unzip")

	require.Equal(t, "base.yaml", results.deletions[0], "could not get correct new deletions")
}

func TestCalculateTemplateAbsolutePathPositiveScenario(t *testing.T) {
	configuredTemplateDirectory := filepath.Join(os.TempDir(), "templates")
	defer os.RemoveAll(configuredTemplateDirectory)

	t.Run("positive scenarios", func(t *testing.T) {
		zipFilePathsExpectedPathsMap := map[string]string{
			"nuclei-templates/cve/test.yaml":      filepath.Join(configuredTemplateDirectory, "cve/test.yaml"),
			"nuclei-templates/cve/test/test.yaml": filepath.Join(configuredTemplateDirectory, "cve/test/test.yaml"),
		}

		for filePathFromZip, expectedTemplateAbsPath := range zipFilePathsExpectedPathsMap {
			calculatedTemplateAbsPath, skipFile, err := calculateTemplateAbsolutePath(filePathFromZip, configuredTemplateDirectory)
			require.Nil(t, err)
			require.Equal(t, expectedTemplateAbsPath, calculatedTemplateAbsPath)
			require.False(t, skipFile)
		}
	})
}

func zipFromDirectory(zipPath, directory string) error {
	file, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer file.Close()

	w := zip.NewWriter(file)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		f, err := w.Create(strings.TrimPrefix(path, directory))
		if err != nil {
			return err
		}
		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}
		return nil
	}
	return filepath.Walk(directory, walker)
}
