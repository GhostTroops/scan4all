package shodanidb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"errors"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/uncover/sources"
	iputil "github.com/projectdiscovery/utils/ip"
)

var (
	URL = "https://internetdb.shodan.io/%s"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "shodan-idb"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	results := make(chan sources.Result)

	if !iputil.IsIP(query.Query) && !iputil.IsCIDR(query.Query) {
		return nil, errors.New("only ip/cidr are accepted")
	}

	go func() {
		defer close(results)

		shodanRequest := &ShodanRequest{Query: query.Query}
		agent.query(ctx, URL, session, shodanRequest, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, shodanRequest *ShodanRequest) (*http.Response, error) {
	shodanURL := fmt.Sprintf(URL, url.QueryEscape(shodanRequest.Query))
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, shodanURL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(ctx context.Context, URL string, session *sources.Session, shodanRequest *ShodanRequest, results chan sources.Result) {
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
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return
	}
	for ip := range ipChan {
		if ctx.Err() != nil {
			return
		}
		resp, err := agent.queryURL(ctx, session, URL, &ShodanRequest{Query: ip})
		if err != nil {
			if !sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err}) {
				return
			}
			continue
		}

		shodanResponse := &ShodanResponse{}
		if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
			if !sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err}) {
				return
			}
			continue
		}

		result := sources.Result{Source: agent.Name(), IP: shodanResponse.IP}
		result.Raw, _ = json.Marshal(shodanResponse)
		for _, port := range shodanResponse.Ports {
			result.Port = port
			if !sources.SendResult(ctx, results, result) {
				return
			}
			for _, hostname := range shodanResponse.Hostnames {
				result.Host = hostname
				if !sources.SendResult(ctx, results, result) {
					return
				}
			}
		}
	}
}

type ShodanRequest struct {
	Query string
}
