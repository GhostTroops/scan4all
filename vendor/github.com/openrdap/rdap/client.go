// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/openrdap/rdap/bootstrap"
)

// Client implements an RDAP client.
//
// This client executes RDAP requests, and returns the responses as Go values.
//
// Quick usage:
//   client := &rdap.Client{}
//   domain, err := client.QueryDomain("example.cz")
//
//   if err == nil {
//     fmt.Printf("Handle=%s Domain=%s\n", domain.Handle, domain.LDHName)
//   }
// The QueryDomain(), QueryAutnum(), and QueryIP() methods all provide full contact information, and timeout after 30s.
//
// Normal usage:
//   // Query example.cz.
//   req := &rdap.Request{
//     Type: rdap.DomainRequest,
//     Query: "example.cz",
//   }
//
//   client := &rdap.Client{}
//   resp, err := client.Do(req)
//
//   if domain, ok := resp.Object.(*rdap.Domain); ok {
//     fmt.Printf("Handle=%s Domain=%s\n", domain.Handle, domain.LDHName)
//   }
//
// Advanced usage:
//
// This demonstrates custom FetchRoles, a custom Context, a custom HTTP client,
// a custom Bootstrapper, and a custom timeout.
//   // Nameserver query on rdap.nic.cz.
//   server, _ := url.Parse("https://rdap.nic.cz")
//   req := &rdap.Request{
//     Type: rdap.NameserverRequest,
//     Query: "a.ns.nic.cz",
//     FetchRoles: []string{"all"},
//     Timeout: time.Second * 45, // Custom timeout.
//
//     Server: server,
//   }
//
//   req = req.WithContext(ctx) // Custom context (see https://blog.golang.org/context).
//
//   client := &rdap.Client{}
//   client.HTTP = &http.Client{} // Custom HTTP client.
//   client.Bootstrap = &bootstrap.Client{} // Custom bootstapper.
//
//   resp, err := client.Do(req)
//
//   if ns, ok := resp.Object.(*rdap.Nameserver); ok {
//     fmt.Printf("Handle=%s Domain=%s\n", ns.Handle, ns.LDHName)
//   }
type Client struct {
	HTTP      *http.Client
	Bootstrap *bootstrap.Client

	// Optional callback function for verbose messages.
	Verbose func(text string)

	ServiceProviderExperiment bool
	UserAgent                 string
}

func (c *Client) Do(req *Request) (*Response, error) {
	// Response struct.
	resp := &Response{}

	// Bad query?
	if req == nil {
		return nil, &ClientError{
			Type: InputError,
			Text: "nil Request",
		}
	}

	// Init HTTP client?
	if c.HTTP == nil {
		c.HTTP = &http.Client{}
	}

	// Init Bootstrap client?
	if c.Bootstrap == nil {
		c.Bootstrap = &bootstrap.Client{}
	}

	// Init Verbose callback?
	if c.Verbose == nil {
		c.Verbose = func(text string) {}
	}

	c.Verbose("")
	c.Verbose(fmt.Sprintf("client: Running..."))
	c.Verbose(fmt.Sprintf("client: Request type  : %s", req.Type))
	c.Verbose(fmt.Sprintf("client: Request query : %s", req.Query))

	var reqs []*Request

	// Need to bootstrap the query?
	if req.Server != nil {
		c.Verbose(fmt.Sprintf("client: Request URL   : %s", req.URL()))

		reqs = []*Request{req}
	} else if req.Server == nil {
		c.Verbose("client: Request URL   : TBD, bootstrap required")

		var bootstrapType *bootstrap.RegistryType = bootstrapTypeFor(req)

		if bootstrapType == nil || (*bootstrapType == bootstrap.ServiceProvider && !c.ServiceProviderExperiment) {
			return nil, &ClientError{
				Type: BootstrapNotSupported,
				Text: fmt.Sprintf("Cannot run query type '%s' without a server URL, "+
					"the server must be specified",
					req.Type),
			}
		}

		origBootstrapVerbose := c.Bootstrap.Verbose
		c.Bootstrap.Verbose = c.Verbose
		defer func() {
			c.Bootstrap.Verbose = origBootstrapVerbose
		}()

		question := &bootstrap.Question{
			RegistryType: *bootstrapType,
			Query:        req.Query,
		}
		question = question.WithContext(req.Context())

		var answer *bootstrap.Answer
		var err error

		answer, err = c.Bootstrap.Lookup(question)
		resp.BootstrapAnswer = answer

		if err != nil {
			return resp, err
		}

		// No URLs to query?
		if len(answer.URLs) == 0 {
			return resp, &ClientError{
				Type: BootstrapNoMatch,
				Text: fmt.Sprintf("No RDAP servers found for '%s'", question.Query),
			}
		}

		for _, u := range answer.URLs {
			reqs = append(reqs, req.WithServer(u))
		}
	}

	for i, r := range reqs {
		c.Verbose(fmt.Sprintf("client: RDAP URL #%d is %s", i, r.URL()))
	}

	for _, r := range reqs {
		c.Verbose(fmt.Sprintf("client: GET %s", r.URL()))

		httpResponse := c.get(r)
		resp.HTTP = append(resp.HTTP, httpResponse)

		if httpResponse.Error != nil {
			c.Verbose(fmt.Sprintf("client: error: %s",
				httpResponse.Error))

			if r.Context().Err() == context.DeadlineExceeded {
				return resp, httpResponse.Error
			}

			// Continues to the next RDAP server.
		} else {
			hrr := httpResponse.Response

			c.Verbose(fmt.Sprintf("client: status-code=%d, content-type=%s, length=%d bytes, duration=%s",
				hrr.StatusCode,
				hrr.Header.Get("Content-Type"),
				len(httpResponse.Body),
				httpResponse.Duration))

			if len(httpResponse.Body) > 0 && hrr.StatusCode >= 200 && hrr.StatusCode <= 299 {
				// Decode the response.
				decoder := NewDecoder(httpResponse.Body)

				resp.Object, httpResponse.Error = decoder.Decode()

				if httpResponse.Error != nil {
					c.Verbose(fmt.Sprintf("client: Error decoding response: %s",
						httpResponse.Error))
					continue
				}

				c.Verbose("client: Successfully decoded response")

				// Implement additional fetches here.

				return resp, nil
			} else if hrr.StatusCode == 404 {
				return resp, &ClientError{
					Type: ObjectDoesNotExist,
					Text: fmt.Sprintf("RDAP server returned 404, object does not exist."),
				}
			}
		}
	}

	return resp, &ClientError{
		Type: NoWorkingServers,
		Text: fmt.Sprintf("No RDAP servers responded successfully (tried %d server(s))",
			len(reqs)),
	}
}

func (c *Client) get(rdapReq *Request) *HTTPResponse {
	// HTTPResponse stores the URL, http.Response, response body...
	httpResponse := &HTTPResponse{
		URL: rdapReq.URL().String(),
	}

	start := time.Now()

	// Setup the HTTP request.
	req, err := http.NewRequest("GET", httpResponse.URL, nil)
	if err != nil {
		httpResponse.Error = err
		httpResponse.Duration = time.Since(start)
		return httpResponse
	}

	// Optionally add User-Agent header.
	if c.UserAgent != "" {
		req.Header.Add("User-Agent", c.UserAgent)
	}

	// HTTP Accept header.
	req.Header.Add("Accept", "application/rdap+json, application/json")

	// Add context for timeout.
	req = req.WithContext(rdapReq.Context())

	// Make the HTTP request.
	resp, err := c.HTTP.Do(req)
	httpResponse.Response = resp

	// Handle errors such as "remote doesn't speak HTTP"...
	if err != nil {
		httpResponse.Error = err
		httpResponse.Duration = time.Since(start)

		return httpResponse
	}

	defer resp.Body.Close()
	httpResponse.Body, httpResponse.Error = ioutil.ReadAll(resp.Body)

	httpResponse.Duration = time.Since(start)

	return httpResponse
}

// QueryDomain makes an RDAP request for the |domain|.
//
// Full contact information (where available) is provided. The timeout is 30s.
func (c *Client) QueryDomain(domain string) (*Domain, error) {
	req := &Request{
		Type:  DomainRequest,
		Query: domain,
	}

	resp, err := c.doQuickRequest(req)
	if err != nil {
		return nil, err
	}

	if domain, ok := resp.Object.(*Domain); ok {
		return domain, nil
	} else if respError, ok := resp.Object.(*Error); ok {
		return nil, clientErrorFromRDAPError(respError)
	}

	return nil, &ClientError{
		Type: WrongResponseType,
		Text: "The server returned a non-Domain RDAP response",
	}
}

func (c *Client) doQuickRequest(req *Request) (*Response, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*30)
	defer cancelFunc()

	req = req.WithContext(ctx)
	resp, err := c.Do(req)

	return resp, err
}

// QueryAutnum makes an RDAP request for the Autonomous System Number (ASN) |autnum|.
//
// |autnum| is an ASN string, e.g. "AS2856" or "5400".
//
// Full contact information (where available) is provided. The timeout is 30s.
func (c *Client) QueryAutnum(autnum string) (*Autnum, error) {
	req := &Request{
		Type:  AutnumRequest,
		Query: autnum,
	}

	resp, err := c.doQuickRequest(req)
	if err != nil {
		return nil, err
	}

	if autnum, ok := resp.Object.(*Autnum); ok {
		return autnum, nil
	} else if respError, ok := resp.Object.(*Error); ok {
		return nil, clientErrorFromRDAPError(respError)
	}

	return nil, &ClientError{
		Type: WrongResponseType,
		Text: "The server returned a non-Autnum RDAP response",
	}
}

// QueryIP makes an RDAP request for the IPv4/6 address |ip|, e.g. "192.0.2.0" or "2001:db8::".
//
// Full contact information (where available) is provided. The timeout is 30s.
func (c *Client) QueryIP(ip string) (*IPNetwork, error) {
	req := &Request{
		Type:  IPRequest,
		Query: ip,
	}

	resp, err := c.doQuickRequest(req)
	if err != nil {
		return nil, err
	}

	if ipNet, ok := resp.Object.(*IPNetwork); ok {
		return ipNet, nil
	} else if respError, ok := resp.Object.(*Error); ok {
		return nil, clientErrorFromRDAPError(respError)
	}

	return nil, &ClientError{
		Type: WrongResponseType,
		Text: "The server returned a non-IPNetwork RDAP response",
	}
}

func bootstrapTypeFor(req *Request) *bootstrap.RegistryType {
	b := new(bootstrap.RegistryType)

	switch req.Type {
	case DomainRequest:
		*b = bootstrap.DNS
	case AutnumRequest:
		*b = bootstrap.ASN
	case EntityRequest:
		*b = bootstrap.ServiceProvider
	case IPRequest:
		if strings.Contains(req.Query, ":") {
			*b = bootstrap.IPv6
		} else {
			*b = bootstrap.IPv4
		}
	default:
		b = nil
	}

	return b
}
