package asnmap

import (
	"bufio"
	"crypto/tls"
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

	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"golang.org/x/net/proxy"
)

const serverURL = "https://api.asnmap.sh/"

type Client struct {
	url  *url.URL
	http http.Client
}

// generatefullURL creates the complete URL with path, scheme, and host
func generateFullURL(host string) (*url.URL, error) {
	rawURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	if !stringsutil.EqualFoldAny(rawURL.Scheme, "http", "https") {
		return nil, errors.New("Host should start with http or https.")
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

	// ignore expired SSL certificates
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := Client{
		url:  URL,
		http: http.Client{Transport: transCfg},
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
	defer file.Close()
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
			Proxy:           http.ProxyURL(proxyurl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return proxyurl, nil
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", proxyurl.Host, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		c.http.Transport = &http.Transport{
			Dial: dialer.Dial,
		}
		return proxyurl, nil
	default:
		return nil, fmt.Errorf("invalid proxy scheme: %s", proxyurl.Scheme)
	}
}

func generateRawQuery(query, value string) string {
	return query + "=" + value
}

func (c Client) makeRequest() ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, c.url.String(), nil)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(res.Body)
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
	switch IdentifyInput(input) {
	case ASN:
		inputToStore = strings.TrimPrefix(strings.ToLower(input), "as")
		c.url.RawQuery = generateRawQuery("asn", inputToStore)
	case ASNID:
		c.url.RawQuery = generateRawQuery("asn", input)
	case IP:
		c.url.RawQuery = generateRawQuery("ip", input)
	case Org:
		c.url.RawQuery = generateRawQuery("org", input)
	case Unknown:
		return nil, errors.New("unknown type")
	}

	resp, err := c.makeRequest()
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
