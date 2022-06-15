package uncover

import (
	"io"
	"net/http"
)

func NewHTTPRequest(method, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Uncover - FOSS Project (github.com/projectdiscovery/uncover)")
	return request, nil
}
