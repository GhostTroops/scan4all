package asnmap

import (
	"net/http"
	"strconv"
	"time"
)

const (
	maxRetries = 3
	// a misbehaving Retry-After should not stall the run
	maxRetryWait = 10 * time.Second
)

// do sends req, retrying rate limited and transient server failures with exponential backoff
func (c Client) do(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		res, err := c.http.Do(req)
		if err != nil || !isRetryable(res.StatusCode) || attempt == maxRetries {
			return res, err
		}
		wait := retryWait(res.Header.Get("Retry-After"), attempt)
		_ = res.Body.Close()
		time.Sleep(wait)
	}
}

func isRetryable(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func retryWait(retryAfter string, attempt int) time.Duration {
	wait := time.Second << attempt
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
		wait = time.Duration(seconds) * time.Second
	}
	return min(wait, maxRetryWait)
}
