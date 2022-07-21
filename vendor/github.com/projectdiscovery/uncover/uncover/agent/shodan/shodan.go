package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	URL = "https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d"
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
	return "shodan"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.Shodan == "" {
		return nil, errors.New("empty shodan keys")
	}
	results := make(chan uncover.Result)

	go func() {
		defer close(results)

		currentPage := 1
		var numberOfResults, totalResults int
		for {
			shodanRequest := &ShodanRequest{
				Query: query.Query,
				Page:  currentPage,
			}

			shodanResponse := agent.query(URL, session, shodanRequest, results)
			if shodanResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(shodanResponse.Results)
			if totalResults == 0 {
				totalResults = shodanResponse.Total
			}

			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(shodanResponse.Results) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *uncover.Session, URL string, shodanRequest *ShodanRequest) (*http.Response, error) {
	shodanURL := fmt.Sprintf(URL, session.Keys.Shodan, url.QueryEscape(shodanRequest.Query), shodanRequest.Page)
	request, err := uncover.NewHTTPRequest(http.MethodGet, shodanURL, nil)
	if err != nil {
		return nil, err
	}
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, shodanRequest *ShodanRequest, results chan uncover.Result) *ShodanResponse {
	// query certificates
	resp, err := agent.queryURL(session, URL, shodanRequest)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	shodanResponse := &ShodanResponse{}
	if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, shodanResult := range shodanResponse.Results {
		result := uncover.Result{Source: agent.Name()}
		if port, ok := shodanResult["port"]; ok {
			result.Port = int(port.(float64))
		}
		if ip, ok := shodanResult["ip_str"]; ok {
			result.IP = ip.(string)
		}
		// has hostnames?
		if hostnames, ok := shodanResult["hostnames"]; ok {
			if _, ok := hostnames.([]interface{}); ok {
				for _, hostname := range hostnames.([]interface{}) {
					result.Host = fmt.Sprint(hostname)
				}
			}
			raw, _ := json.Marshal(shodanResult)
			result.Raw = raw
			results <- result
		} else {
			raw, _ := json.Marshal(shodanResult)
			result.Raw = raw
			// only ip
			results <- result
		}
	}

	return shodanResponse
}

type ShodanRequest struct {
	Query string
	Page  int
}
