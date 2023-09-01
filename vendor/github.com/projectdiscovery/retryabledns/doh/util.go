package doh

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewHttpClientWithTimeout(timeout time.Duration) *http.Client {
	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	return httpClient
}
