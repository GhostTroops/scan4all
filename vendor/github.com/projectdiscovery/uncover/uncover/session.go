package uncover

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

type Session struct {
	Keys   *Keys
	Client *http.Client
}

func NewSession(keys *Keys, timeout int) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	session := &Session{
		Client: client,
		Keys:   keys,
	}

	return session, nil
}

func (s *Session) Do(request *http.Request) (*http.Response, error) {
	request.Header.Set("Connection", "close")
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, errors.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	// var f *os.File
	// var err error
	// if _, _, ok := request.BasicAuth(); ok {
	// 	f, err = os.Open("/Users/marcornvh/go/src/github.com/projectdiscovery/uncover/uncover/agent/censys/example.json")
	// } else {
	// 	f, err = os.Open("/Users/marcornvh/go/src/github.com/projectdiscovery/uncover/uncover/agent/shodan/example.json")
	// }

	if err != nil {
		return nil, err
	}

	// resp := &http.Response{
	// 	StatusCode: 200,
	// 	Body:       f,
	// }

	return resp, nil
}
