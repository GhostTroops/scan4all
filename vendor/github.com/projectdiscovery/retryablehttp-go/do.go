package retryablehttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

// PassthroughErrorHandler is an ErrorHandler that directly passes through the
// values from the net/http library for the final request. The body is not
// closed.
func PassthroughErrorHandler(resp *http.Response, err error, _ int) (*http.Response, error) {
	return resp, err
}

// Do wraps calling an HTTP method with retries.
func (c *Client) Do(req *Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Create a main context that will be used as the main timeout. A zero or
	// negative timeout means no overall deadline (otherwise WithTimeout would
	// create an already-expired context and abort before the first retry).
	mainCtx := context.Background()
	if c.options.Timeout > 0 {
		var cancel context.CancelFunc
		mainCtx, cancel = context.WithTimeout(context.Background(), c.options.Timeout)
		defer cancel()
	}

	retryMax := c.options.RetryMax
	if ctxRetryMax := req.Context().Value(RETRY_MAX); ctxRetryMax != nil {
		if maxRetriesParsed, ok := ctxRetryMax.(int); ok {
			retryMax = maxRetriesParsed
		}
	}

retryLoop:
	for i := 0; ; i++ {
		// request body can be read multiple times
		// hence no need to rewind it
		if c.RequestLogHook != nil {
			c.RequestLogHook(req.Request, i)
		}

		if c.options.Trace {
			c.wrapContextWithTrace(req)
		}

		resp, err = c.send(c.HTTPClient, req)

		// Check if we should continue with retries.
		checkOK, checkErr := c.CheckRetry(req.Context(), resp, err)

		// if err is equal to missing minor protocol version retry with http/2
		if err != nil && stringsutil.ContainsAny(err.Error(), "net/http: HTTP/1.x transport connection broken: malformed HTTP version \"HTTP/2\"", "net/http: HTTP/1.x transport connection broken: malformed HTTP response") {
			resp, err = c.send(c.HTTPClient2, req)
			checkOK, checkErr = c.CheckRetry(req.Context(), resp, err)
		}

		if err != nil {
			// Increment the failure counter as the request failed
			req.Metrics.Failures++
		} else {
			// Call this here to maintain the behavior of logging all requests,
			// even if CheckRetry signals to stop.
			if c.ResponseLogHook != nil {
				// Call the response logger function if provided.
				c.ResponseLogHook(resp)
			}
		}

		// Now decide if we should continue.
		if !checkOK {
			if checkErr != nil {
				err = checkErr
			}
			c.closeIdleConnections()
			return resp, err
		}

		// We do this before drainBody beause there's no need for the I/O if
		// we're breaking out
		remain := retryMax - i
		if remain <= 0 {
			break
		}

		// Increment the retries counter as we are going to do one more retry
		req.Metrics.Retries++

		// We're going to retry, consume any response to reuse the connection.
		if err == nil && resp != nil {
			c.drainBody(req, resp)
		}

		// Wait for the time specified by backoff then retry.
		// If the context is cancelled however, return.
		wait := c.Backoff(c.options.RetryWaitMin, c.options.RetryWaitMax, i, resp)

		// Wait for the backoff period, but stop early if either the overall
		// timeout (mainCtx) or the request context is done. A timer is used
		// instead of time.After so it is released immediately on early exit
		// rather than lingering for the full backoff duration.
		timer := time.NewTimer(wait)
		select {
		case <-mainCtx.Done():
			timer.Stop()
			err = mainCtx.Err()
			break retryLoop
		case <-req.Context().Done():
			timer.Stop()
			c.closeIdleConnections()
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}

	if c.ErrorHandler != nil {
		c.closeIdleConnections()
		return c.ErrorHandler(resp, err, retryMax+1)
	}

	// By default, we close the response body and return an error without
	// returning the response
	if resp != nil {
		_ = resp.Body.Close()
	}
	c.closeIdleConnections()
	return nil, fmt.Errorf("%s %s giving up after %d attempts: %w", req.Method, req.URL, retryMax+1, err)
}

// send makes one attempt at req using hc. With digest auth, the attempt sends a
// clone of req and answers a Digest challenge in the 401 response by sending
// another clone with an Authorization header; if no challenge can be answered,
// it returns the 401. Do sends the first attempt and the HTTP/2 fallback
// through send, so the two differ only in the client.
func (c *Client) send(hc *http.Client, req *Request) (*http.Response, error) {
	if !req.hasAuth() || req.Auth.Type != DigestAuth {
		return hc.Do(req.Request)
	}

	// Both requests send a copy of the body. A server that rejects the first
	// one may stop reading partway, which would leave req.Body partly read
	// for the second request and for later retries.
	body, err := readBody(req.Request)
	if err != nil {
		return nil, fmt.Errorf("read body for digest auth: %w", err)
	}
	resp, err := hc.Do(withBody(req.Request, body))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge, ok := findDigestChallenge(resp.Header)
	if !ok {
		return resp, nil
	}
	c.drainBody(req, resp)

	authReq := withBody(req.Request, body)
	authorization := challenge.authorization(req.Auth, authReq.Method, authReq.URL.RequestURI(), body, rand.Text())
	authReq.Header.Set("Authorization", authorization)
	return hc.Do(authReq)
}

// readBody returns a copy of the request body, or nil if it has none. It reads
// through GetBody when set, which leaves req.Body as it is.
func readBody(req *http.Request) ([]byte, error) {
	body := req.Body
	if req.GetBody != nil {
		var err error
		if body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	if body == nil || body == http.NoBody {
		return nil, nil
	}
	defer func() {
		_ = body.Close()
	}()
	return io.ReadAll(body)
}

// withBody returns a clone of req that reads its body from body.
func withBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	if body != nil {
		clone.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		clone.Body, _ = clone.GetBody()
	}
	return clone
}

// Try to read the response body so we can reuse this connection.
func (c *Client) drainBody(req *Request, resp *http.Response) {
	_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, c.options.RespReadLimit))
	if err != nil {
		req.Metrics.DrainErrors++
	}
	_ = resp.Body.Close()
}

const closeConnectionsCounter = 100

func (c *Client) closeIdleConnections() {
	if c.options.KillIdleConn {
		if c.requestCounter.Load() < closeConnectionsCounter {
			c.requestCounter.Add(1)
		} else {
			c.requestCounter.Store(0)
			c.HTTPClient.CloseIdleConnections()
			c.HTTPClient2.CloseIdleConnections()
		}
	}
}

func (c *Client) wrapContextWithTrace(req *Request) {
	traceInfo := &TraceInfo{}
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			traceInfo.GotConn = TraceEventInfo{
				Time: time.Now(),
				Info: connInfo,
			}
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			traceInfo.DNSDone = TraceEventInfo{
				Time: time.Now(),
				Info: dnsInfo,
			}
		},
		GetConn: func(hostPort string) {
			traceInfo.GetConn = TraceEventInfo{
				Time: time.Now(),
				Info: hostPort,
			}
		},
		PutIdleConn: func(err error) {
			traceInfo.PutIdleConn = TraceEventInfo{
				Time: time.Now(),
				Info: err,
			}
		},
		GotFirstResponseByte: func() {
			traceInfo.GotFirstResponseByte = TraceEventInfo{
				Time: time.Now(),
			}
		},
		Got100Continue: func() {
			traceInfo.Got100Continue = TraceEventInfo{
				Time: time.Now(),
			}
		},
		DNSStart: func(di httptrace.DNSStartInfo) {
			traceInfo.DNSStart = TraceEventInfo{
				Time: time.Now(),
				Info: di,
			}
		},
		ConnectStart: func(network, addr string) {
			traceInfo.ConnectStart = TraceEventInfo{
				Time: time.Now(),
				Info: struct {
					Network, Addr string
				}{network, addr},
			}
		},
		ConnectDone: func(network, addr string, err error) {
			if err == nil {
				traceInfo.ConnectDone = TraceEventInfo{
					Time: time.Now(),
					Info: struct {
						Network, Addr string
						Error         error
					}{network, addr, err},
				}
			}
		},
		TLSHandshakeStart: func() {
			traceInfo.TLSHandshakeStart = TraceEventInfo{
				Time: time.Now(),
			}
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err == nil {
				traceInfo.TLSHandshakeDone = TraceEventInfo{
					Time: time.Now(),
					Info: struct {
						ConnectionState tls.ConnectionState
						Error           error
					}{cs, err},
				}
			}
		},
		WroteHeaders: func() {
			traceInfo.WroteHeaders = TraceEventInfo{
				Time: time.Now(),
			}
		},
		WroteRequest: func(wri httptrace.WroteRequestInfo) {
			traceInfo.WroteRequest = TraceEventInfo{
				Time: time.Now(),
				Info: wri,
			}
		},
	}
	req.TraceInfo = traceInfo

	req.Request = req.Request.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}
