package pdcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	urlutil "github.com/projectdiscovery/utils/url"
	"gopkg.in/yaml.v3"
)

var (
	PDCPDir      = filepath.Join(folderutil.HomeDirOrDefault(""), ".pdcp")
	PDCPCredFile = filepath.Join(PDCPDir, "credentials.yaml")
	ErrNoCreds   = fmt.Errorf("no credentials found in %s", PDCPDir)
)

const (
	userProfileURL   = "https://%s/v1/user?utm_source=%s"
	apiKeyEnv        = "PDCP_API_KEY"
	apiServerEnv     = "PDCP_API_SERVER"
	ApiKeyHeaderName = "X-Api-Key"
	dashBoardEnv     = "PDCP_DASHBOARD_URL"
)

// apiClient sends the API key, so it must verify the server certificate.
// The retryablehttp default clients skip verification.
var apiClient = newAPIClient()

func newAPIClient() *retryablehttp.Client {
	transport := retryablehttp.DefaultReusePooledTransport()
	// fastdialer DialTLS does not verify certificates, so net/http does the
	// TLS handshake over the fastdialer connection.
	transport.DialTLSContext = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	opts := retryablehttp.DefaultOptionsSingle
	opts.HttpClient = &http.Client{Transport: transport}
	// a certificate error does not go away on retry
	defaultRetry := retryablehttp.DefaultRetryPolicy()
	opts.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return false, nil
		}
		return defaultRetry(ctx, resp, err)
	}
	return retryablehttp.NewClient(opts)
}

type PDCPCredentials struct {
	Username string `yaml:"username"`
	Email    string `yaml:"email"`
	APIKey   string `yaml:"api-key"`
	Server   string `yaml:"server"`
}

type PDCPUserProfileResponse struct {
	UserName string `json:"name"`
	Email    string `json:"email"`
	// there are more fields but we don't need them
	/// below fields are added later on and not part of the response
}

// PDCPCredHandler is interface for adding / retrieving pdcp credentials
// from file system
type PDCPCredHandler struct{}

// GetCreds retrieves the credentials from the file system or environment variables
func (p *PDCPCredHandler) GetCreds() (*PDCPCredentials, error) {
	credsFromEnv := p.getCredsFromEnv()
	if credsFromEnv != nil {
		return credsFromEnv, nil
	}
	if !fileutil.FolderExists(PDCPDir) || !fileutil.FileExists(PDCPCredFile) {
		return nil, ErrNoCreds
	}
	bin, err := os.Open(PDCPCredFile)
	if err != nil {
		return nil, err
	}
	// for future use-cases
	var creds []PDCPCredentials
	err = yaml.NewDecoder(bin).Decode(&creds)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrNoCreds
	}
	return &creds[0], nil
}

// getCredsFromEnv retrieves the credentials from the environment
// if not or incomplete credentials are found it return nil
func (p *PDCPCredHandler) getCredsFromEnv() *PDCPCredentials {
	apiKey := env.GetEnvOrDefault(apiKeyEnv, "")
	apiServer := env.GetEnvOrDefault(apiServerEnv, DefaultApiServer)
	if apiKey == "" || apiServer == "" {
		return nil
	}
	return &PDCPCredentials{APIKey: apiKey, Server: apiServer}
}

// SaveCreds saves the credentials to the file system
func (p *PDCPCredHandler) SaveCreds(resp *PDCPCredentials) error {
	if resp == nil {
		return fmt.Errorf("invalid response")
	}
	if !fileutil.FolderExists(PDCPDir) {
		_ = fileutil.CreateFolder(PDCPDir)
	}
	bin, err := yaml.Marshal([]*PDCPCredentials{resp})
	if err != nil {
		return err
	}
	return os.WriteFile(PDCPCredFile, bin, 0600)
}

// ValidateAPIKey validates the api key and retrieves associated user metadata like username
// from given api server/host
func (p *PDCPCredHandler) ValidateAPIKey(key string, host string, toolName string) (*PDCPCredentials, error) {
	// get address from url
	urlx, err := urlutil.Parse(host)
	if err != nil {
		return nil, err
	}
	req, err := retryablehttp.NewRequest("GET", fmt.Sprintf(userProfileURL, urlx.Host, toolName), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(ApiKeyHeaderName, key)
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var profile PDCPUserProfileResponse
	err = json.Unmarshal(bin, &profile)
	if err != nil {
		return nil, err
	}
	if profile.Email == "" {
		return nil, fmt.Errorf("invalid response from server got %v", string(bin))
	}
	return &PDCPCredentials{Username: profile.UserName, Email: profile.Email, APIKey: key, Server: host}, nil
}

func init() {
	DashBoardURL = env.GetEnvOrDefault("PDCP_DASHBOARD_URL", DashBoardURL)
}
