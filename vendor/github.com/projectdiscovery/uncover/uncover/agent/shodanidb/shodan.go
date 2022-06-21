package shodanidb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/uncover/uncover"
)

const (
	URL = "https://internetdb.shodan.io/%s"
)

type Agent struct {
	options *uncover.AgentOptions
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "shodan-idb"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	results := make(chan uncover.Result)

	if !iputil.IsIP(query.Query) && !iputil.IsCIDR(query.Query) {
		return nil, errors.New("only ip/cidr are accepted")
	}

	go func() {
		defer close(results)

		shodanRequest := &ShodanRequest{Query: query.Query}
		agent.query(URL, session, shodanRequest, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, shodanRequest *ShodanRequest) (*http.Response, error) {
	shodanURL := fmt.Sprintf(URL, url.QueryEscape(shodanRequest.Query))
	request, err := uncover.NewHTTPRequest(http.MethodGet, shodanURL, nil)
	if err != nil {
		return nil, err
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, shodanRequest *ShodanRequest, results chan uncover.Result) {
	var query string
	if iputil.IsIP(shodanRequest.Query) {
		if iputil.IsIPv4(shodanRequest.Query) {
			query = iputil.AsIPV4CIDR(shodanRequest.Query)
		} else if iputil.IsIPv6(shodanRequest.Query) {
			query = iputil.AsIPV6CIDR(shodanRequest.Query)
		}
	} else {
		query = shodanRequest.Query
	}
	ipChan, err := mapcidr.IPAddressesAsStream(query)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return
	}
	for ip := range ipChan {
		resp, err := agent.queryURL(session, URL, &ShodanRequest{Query: ip})
		if err != nil {
			results <- uncover.Result{Source: agent.Name(), Error: err}
			continue
		}

		shodanResponse := &ShodanResponse{}
		if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
			results <- uncover.Result{Source: agent.Name(), Error: err}
			continue
		}

		// we must output all combinations of ip/hostname with ports
		result := uncover.Result{Source: agent.Name(), IP: shodanResponse.IP}
		result.Raw, _ = json.Marshal(shodanResponse)
		for _, port := range shodanResponse.Ports {
			result.Port = port
			results <- result
			for _, hostname := range shodanResponse.Hostnames {
				result.Host = hostname
				results <- result
			}
		}
	}
}

type ShodanRequest struct {
	Query string
}
