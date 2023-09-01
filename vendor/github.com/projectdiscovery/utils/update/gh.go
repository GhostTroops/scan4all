package updateutils

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/google/go-github/v30/github"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	"golang.org/x/oauth2"
)

var (
	extIfFound             = ".exe"
	ErrNoAssetFound        = errorutil.NewWithFmt("update: could not find release asset for your platform (%s/%s)")
	SkipCheckSumValidation = false // by default checksum of gh assets is verified with checksums file present in release
)

// AssetFileCallback function is executed on every file in unpacked asset . if returned error
// is not nil furthur processing of asset file is stopped
type AssetFileCallback func(path string, fileInfo fs.FileInfo, data io.Reader) error

// GHReleaseDownloader fetches and reads release of a gh repo
type GHReleaseDownloader struct {
	assetName     string // required assetName given as input
	repoName      string // we assume toolname and repoName are always same
	fullAssetName string // full asset name of asset that contains tool for this platform
	organization  string // organization name of repo
	Format        AssetFormat
	AssetID       int
	Latest        *github.RepositoryRelease
	client        *github.Client
	httpClient    *http.Client
}

// NewghReleaseDownloader returns GHRD instance
func NewghReleaseDownloader(RepoName string) (*GHReleaseDownloader, error) {
	var orgName, repoName string
	if strings.Contains(RepoName, "/") {
		arr := strings.Split(RepoName, "/")
		if len(arr) != 2 {
			return nil, errorutil.NewWithTag("update", "invalid repo name %v", RepoName)
		}
		orgName = arr[0]
		repoName = arr[1]
	} else {
		orgName = Organization
		repoName = RepoName
	}
	httpClient := &http.Client{
		Timeout: DownloadUpdateTimeout,
	}
	if orgName == "" {
		return nil, errorutil.NewWithTag("update", "organization name cannot be empty")
	}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		httpClient = oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	}
	ghrd := GHReleaseDownloader{client: github.NewClient(httpClient), repoName: repoName, assetName: repoName, httpClient: httpClient, organization: orgName}

	err := ghrd.getLatestRelease()
	return &ghrd, err
}

// SetAssetName: By default RepoName is assumed as ToolName which maynot be the case always setToolName corrects that
func (d *GHReleaseDownloader) SetToolName(toolName string) {
	if toolName != "" {
		d.assetName = toolName
	}
}

// DownloadTool downloads tool and returns bin data
func (d *GHReleaseDownloader) DownloadTool() (*bytes.Buffer, error) {
	if err := d.getToolAssetID(d.Latest); err != nil {
		return nil, err
	}
	resp, err := d.downloadAssetwithID(int64(d.AssetID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if !HideProgressBar {
		bar := pb.New64(resp.ContentLength).SetMaxWidth(100)
		bar.Start()
		resp.Body = bar.NewProxyReader(resp.Body)
		defer bar.Finish()
	}

	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to read response body")
	}
	return bytes.NewBuffer(bin), nil
}

// GetReleaseChecksums tries to download tool checksum if release contains any in map[asset_name]checksum_data format
func (d *GHReleaseDownloader) GetReleaseChecksums() (map[string]string, error) {
	builder := &strings.Builder{}
	builder.WriteString(d.assetName)
	builder.WriteString("_")
	builder.WriteString(strings.TrimPrefix(d.Latest.GetTagName(), "v"))
	builder.WriteString("_")
	builder.WriteString("checksums.txt")
	checksumFileName := builder.String()

	checksumFileAssetID := 0
	for _, v := range d.Latest.Assets {
		if v.GetName() == checksumFileName {
			checksumFileAssetID = int(v.GetID())
		}
	}
	if checksumFileAssetID == 0 {
		return nil, errorutil.NewWithTag("update", "checksum file not in release assets")
	}

	resp, err := d.downloadAssetwithID(int64(checksumFileAssetID))
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to download checksum file")
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to read checksum file")
	}
	data := strings.TrimSpace(string(bin))
	if data == "" {
		return nil, errorutil.NewWithTag("checksum", "something went wrong checksum file is emtpy")
	}
	m := map[string]string{}
	for _, v := range strings.Split(data, "\n") {
		arr := strings.Fields(v)
		if len(arr) != 2 {
			continue
		}
		m[arr[1]] = arr[0]
	}
	return m, nil
}

// GetExecutableFromAsset downloads , validates checksum and only returns tool Binary
func (d *GHReleaseDownloader) GetExecutableFromAsset() ([]byte, error) {
	var bin []byte
	var err error
	getToolCallback := func(path string, fileInfo fs.FileInfo, data io.Reader) error {
		if !strings.EqualFold(strings.TrimSuffix(fileInfo.Name(), extIfFound), d.assetName) {
			return nil
		}
		bin, err = io.ReadAll(data)
		return err
	}

	buff, err := d.DownloadTool()
	if err != nil {
		return nil, err
	}

	var expectedChecksum string
	checksums, err := d.GetReleaseChecksums()
	if checksums != nil {
		expectedChecksum = checksums[d.fullAssetName]
	}
	// verify integrity using checksum
	if expectedChecksum != "" {
		gotChecksumbytes := sha256.Sum256(buff.Bytes())
		gotchecksum := hex.EncodeToString(gotChecksumbytes[:])
		if expectedChecksum != gotchecksum {
			return nil, errorutil.NewWithTag("checksum", "asset file corrupted: checksum mismatch expected %v but got %v", expectedChecksum, gotchecksum)
		} else {
			gologger.Info().Msgf("Verified Integrity of %v", d.fullAssetName)
		}
	}

	_ = UnpackAssetWithCallback(d.Format, bytes.NewReader(buff.Bytes()), getToolCallback)
	return bin, errorutil.WrapfWithNil(err, "executable not found in archive") // Note: WrapfWithNil wraps msg if err != nil
}

// DownloadAssetWithName downloads asset with given name
func (d *GHReleaseDownloader) DownloadAssetWithName(assetname string, showProgressBar bool) (*bytes.Buffer, error) {
	assetID := 0
	for _, v := range d.Latest.Assets {
		if v.GetName() == assetname {
			assetID = int(v.GetID())
		}
	}
	if assetID == 0 {
		return nil, errorutil.New("release asset %v not found", assetname)
	}
	resp, err := d.downloadAssetwithID(int64(assetID))
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to download asset %v", assetname)
	}
	defer resp.Body.Close()

	if showProgressBar {
		bar := pb.New64(resp.ContentLength).SetMaxWidth(100)
		bar.Start()
		resp.Body = bar.NewProxyReader(resp.Body)
		defer bar.Finish()
	}

	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to read resp body")
	}
	return bytes.NewBuffer(bin), nil
}

// DownloadSourceWithCallback downloads source code of latest release and calls callback for each file in archive
func (d *GHReleaseDownloader) DownloadSourceWithCallback(showProgressBar bool, callback AssetFileCallback) error {
	downloadURL := d.Latest.GetZipballURL()

	resp, err := d.httpClient.Get(downloadURL)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to source of %v", d.repoName)
	}
	defer resp.Body.Close()
	if showProgressBar {
		bar := pb.New64(resp.ContentLength).SetMaxWidth(100)
		bar.Start()
		resp.Body = bar.NewProxyReader(resp.Body)
		defer bar.Finish()
	}

	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to read resp body")
	}
	return UnpackAssetWithCallback(Zip, bytes.NewReader(bin), callback)
}

// getLatestRelease returns latest release of error
func (d *GHReleaseDownloader) getLatestRelease() error {
	release, resp, err := d.client.Repositories.GetLatestRelease(context.Background(), d.organization, d.repoName)
	if err != nil {
		errx := errorutil.NewWithErr(err)
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			errx = errx.Msgf("repo %v/%v not found got %v", d.organization, d.repoName)
		} else if _, ok := err.(*github.RateLimitError); ok {
			errx = errx.Msgf("hit github ratelimit while downloading latest release")
		} else if resp != nil && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized) {
			errx = errx.Msgf("gh auth failed try unsetting GITHUB_TOKEN env variable")
		}
		return errx
	}
	d.Latest = release
	return nil
}

// getToolAssetID tries to find assetId of tool required for this platform
func (d *GHReleaseDownloader) getToolAssetID(latest *github.RepositoryRelease) error {
	builder := &strings.Builder{}
	builder.WriteString(d.assetName)
	builder.WriteString("_")
	builder.WriteString(strings.TrimPrefix(latest.GetTagName(), "v"))
	builder.WriteString("_")
	if strings.EqualFold(runtime.GOOS, "darwin") {
		builder.WriteString("macOS")
	} else {
		builder.WriteString(runtime.GOOS)
	}
	builder.WriteString("_")
	builder.WriteString(runtime.GOARCH)

loop:
	for _, v := range latest.Assets {
		asset := v.GetName()
		switch {
		case strings.Contains(asset, Zip.FileExtension()):
			if strings.EqualFold(asset, builder.String()+Zip.FileExtension()) {
				d.AssetID = int(v.GetID())
				d.Format = Zip
				d.fullAssetName = asset
				break loop
			}
		case strings.Contains(asset, Tar.FileExtension()):
			if strings.EqualFold(asset, builder.String()+Tar.FileExtension()) {
				d.AssetID = int(v.GetID())
				d.Format = Tar
				d.fullAssetName = asset
				break loop
			}
		}
	}
	builder.Reset()

	// handle if id is zero (no asset found)
	if d.AssetID == 0 {
		return ErrNoAssetFound.Msgf(runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

// downloadAssetwithID
func (d *GHReleaseDownloader) downloadAssetwithID(id int64) (*http.Response, error) {
	_, rdurl, err := d.client.Repositories.DownloadReleaseAsset(context.Background(), d.organization, d.repoName, id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Get(rdurl)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to download release asset")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errorutil.New("something went wrong got %v while downloading asset, expected status 200", resp.StatusCode)
	}
	if resp.Body == nil {
		return nil, errorutil.New("something went wrong got response without body")
	}
	return resp, nil
}

// UnpackAssetWithCallback unpacks asset and executes callback function on every file in data
func UnpackAssetWithCallback(format AssetFormat, data *bytes.Reader, callback AssetFileCallback) error {
	if format != Zip && format != Tar {
		return errorutil.NewWithTag("unpack", "github asset format not supported. only zip and tar are supported")
	}
	if format == Zip {
		zipReader, err := zip.NewReader(data, data.Size())
		if err != nil {
			return err
		}
		for _, f := range zipReader.File {
			data, err := f.Open()
			if err != nil {
				return err
			}
			if err := callback(f.Name, f.FileInfo(), data); err != nil {
				return err
			}
			_ = data.Close()
		}
	} else if format == Tar {
		gzipReader, err := gzip.NewReader(data)
		if err != nil {
			return err
		}
		tarReader := tar.NewReader(gzipReader)
		// iterate through the files in the archive
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := callback(header.Name, header.FileInfo(), tarReader); err != nil {
				return err
			}
		}
	}
	return nil
}
