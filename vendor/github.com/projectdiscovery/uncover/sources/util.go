package sources

import (
	"io"
	"net/url"

	"github.com/projectdiscovery/retryablehttp-go"
)

func NewHTTPRequest(method, url string, body io.Reader) (*retryablehttp.Request, error) {
	request, err := retryablehttp.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Uncover - FOSS Project (github.com/projectdiscovery/uncover)")
	return request, nil
}

func GetHostname(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	return parsedURL.Hostname(), nil
}
