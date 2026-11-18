package asnmap

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	url "net/url"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
	urlutil "github.com/projectdiscovery/utils/url"
	"golang.org/x/net/proxy"
)

const (
	serverURL = "https://asn.projectdiscovery.io/"
	// the largest ASN responses arrive in a few seconds, so this only trips on a stalled server
	requestTimeout = 30 * time.Second
)

var (
	PDCPApiKey      = env.GetEnvOrDefault("PDCP_API_KEY", "")
	ErrUnAuthorized = errors.New("unauthorized: 401 (get free api key to configure from https://cloud.projectdiscovery.io/?ref=api_key)")
)

func init() {
	if PDCPApiKey == "" {
		pch := pdcp.PDCPCredHandler{}
		if creds, err := pch.GetCreds(); err == nil {
			PDCPApiKey = creds.APIKey
		}
	}
}

type Client struct {
	url  *url.URL
	http *http.Client
}

// generatefullURL creates the complete URL with path, scheme, and host
func generateFullURL(host string) (*url.URL, error) {
	rawURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	if !stringsutil.EqualFoldAny(rawURL.Scheme, "http", "https") {
		return nil, errors.New("host should start with http or https")
	}

	rawURL.Path = "api/v1/asnmap"
	return rawURL, nil
}

// If SERVER_URL env provider use that else use serverURL constant
func getURL() (*url.URL, error) {
	url := os.Getenv("SERVER_URL")
	if url == "" {
		url = serverURL
	}
	return generateFullURL(url)
}

func NewClient() (*Client, error) {
	URL, err := getURL()
	if err != nil {
		return nil, err
	}

	client := Client{
		url:  URL,
		http: &http.Client{Timeout: requestTimeout},
	}
	return &client, nil
}

// SetProxy adds a proxy to the client
func (c *Client) SetProxy(proxyList []string) (*url.URL, error) {
	var (
		proxyUrl *url.URL
		err      error
	)
	for _, p := range proxyList {
		switch {
		case fileutil.FileExists(p):
			proxyUrl, err = c.setProxyFromFile(p)
		default:
			proxyUrl, err = c.setProxy(p)
		}
		if err == nil && proxyUrl != nil {
			return proxyUrl, nil
		}
	}
	return nil, errors.New("no valid proxy found")
}

// setProxyFromFile reads the file contents and tries to set the proxy
func (c *Client) setProxyFromFile(fileName string) (*url.URL, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy == "" {
			continue
		}
		proxyUrl, err := c.setProxy(proxy)
		if err == nil && proxyUrl != nil {
			return proxyUrl, nil
		}
	}
	return nil, fmt.Errorf("no valid proxy found in file '%s'", fileName)
}

// setProxy sets a proxy to the client
func (c *Client) setProxy(proxyString string) (*url.URL, error) {
	// parse the proxy url string
	proxyurl, err := url.Parse(proxyString)
	if err != nil {
		return nil, err
	}

	// try to connect to the proxy
	_, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyurl.Hostname(), proxyurl.Port()), time.Second*5)
	if err != nil {
		return nil, err
	}

	switch proxyurl.Scheme {
	case "http", "https":
		c.http.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyurl),
		}
		return proxyurl, nil
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", proxyurl.Host, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("socks5 dialer does not support DialContext")
		}
		c.http.Transport = &http.Transport{
			DialContext: contextDialer.DialContext,
		}
		return proxyurl, nil
	default:
		return nil, fmt.Errorf("invalid proxy scheme: %s", proxyurl.Scheme)
	}
}

func (c Client) makeRequest(reqURL string) ([]byte, error) {
	if c.http == nil {
		return nil, errors.New("http client is not initialized")
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if PDCPApiKey == "" {
		gologger.Error().Label("asnmap-api").Msgf("missing or invalid api key (get free api key & configure it from https://cloud.projectdiscovery.io/?ref=api_key)")
		return nil, ErrUnAuthorized
	}
	req.Header.Set("X-PDCP-Key", PDCPApiKey)
	res, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusUnauthorized {
		gologger.Error().Msgf("missing or invalid api key (get free api key & configure it from https://cloud.projectdiscovery.io/?ref=api_key)")
		return nil, ErrUnAuthorized
	}

	if res.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(res.Body)
		bodyStr := string(body)
		return nil, fmt.Errorf("bad request: %s", bodyStr)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", res.Status)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return resBody, nil
}

func (c Client) GetDataWithCustomInput(inputToQuery, inputToUseInResponse string) ([]*Response, error) {
	results, err := c.GetData(inputToQuery)
	for _, result := range results {
		result.Input = inputToUseInResponse
	}
	return results, err
}

func (c Client) GetData(input string, medatadas ...string) ([]*Response, error) {
	inputToStore := input
	params := urlutil.NewOrderedParams()
	switch IdentifyInput(input) {
	case ASN:
		inputToStore = strings.TrimPrefix(strings.ToLower(input), "as")
		params.Add("asn", inputToStore)
	case ASNID:
		params.Add("asn", input)
	case IP:
		params.Add("ip", input)
	case Org:
		params.Add("org", input)
	case Unknown:
		return nil, errors.New("unknown type")
	}

	params.Decode(updateutils.GetpdtmParams(Version))

	// copy so concurrent calls don't share the query
	reqURL := *c.url
	reqURL.RawQuery = params.Encode()

	resp, err := c.makeRequest(reqURL.String())
	if err != nil {
		return nil, err
	}

	results := []*Response{}
	err = json.Unmarshal(resp, &results)
	if err != nil {
		return nil, err
	}

	// insert original input in all responses
	for _, result := range results {
		result.Input = inputToStore
	}

	return results, nil
}
