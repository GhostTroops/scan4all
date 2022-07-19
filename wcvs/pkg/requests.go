package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
)

const (
	respSplitHeader = "Web_Cache"
	respSplitValue  = "Vulnerability_Scanner"
)

type requestParams struct {
	repResult  *reportResult
	headers    []string
	values     []string
	parameters []string
	//cookie           oldCookie
	identifier       string
	poison           string
	url              string
	cb               string
	success          string
	bodyString       string
	forcePost        bool
	duplicateHeaders bool
	newCookie        http.Cookie
	m                *sync.Mutex
}

/*type oldCookie struct {
	position int
	oldValue string
}*/

func init() {
}

func getRespSplit() string {
	return "\\r\\n" + respSplitHeader + ": " + respSplitValue
}

func checkPoisoningIndicators(repResult *reportResult, request reportRequest, success string, body string, poison string, statusCode1 int, statusCode2 int, sameBodyLength bool, header http.Header, recursive bool) bool {
	testForResponseSplitting := false
	// forwardheader benutzen keinen mutex. deswegen macht das if hier keinen Sinn
	/*if m == nil {
		result.HasError = true
		msg := fmt.Sprintf("%s: checkPoisoningIndicators: mutex is nil", request.URL)
		Print(msg, Red)
		result.ErrorMessages = append(result.ErrorMessages, msg)
		return testForResponseSplitting
	}*/
	website := &Config.Website
	headerWithPoison := ""
	if header != nil && poison != "" {
		for x := range header {
			if x == respSplitHeader && header.Get(x) == respSplitValue {
				request.Reason = "HTTP Response Splitting"
			}
			if strings.Contains(header.Get(x), poison) {
				headerWithPoison = x
			}
		}
	}

	if request.Reason == "" {
		if poison != "" && strings.Contains(body, poison) {
			request.Reason = "Response Body contained " + poison
		} else if headerWithPoison != "" {
			request.Reason = fmt.Sprintf("%s header contains poison value %s", headerWithPoison, poison)
			testForResponseSplitting = true
		} else if statusCode1 >= 0 && statusCode1 != website.StatusCode && statusCode1 == statusCode2 {
			if !recursive {
				var tmpWebsite WebsiteStruct
				var err error

				count := 3
				for i := 0; i < count; i++ {
					tmpWebsite, err = GetWebsite(Config.Website.Url.String(), true, true)
					if err == nil {
						break
					}
				}
				if err != nil {
					repResult.HasError = true
					msg := fmt.Sprintf("%s: couldn't verify if status code %d is the new default status code, because the verification encountered the following error %d times: %s", request.URL, statusCode1, count, err.Error())
					repResult.ErrorMessages = append(repResult.ErrorMessages, msg)
				} else {
					Config.Website = tmpWebsite
				}
				return checkPoisoningIndicators(repResult, request, success, body, poison, statusCode1, statusCode2, sameBodyLength, header, true)
			} else {
				request.Reason = fmt.Sprintf("Status Code %d differed from %d", statusCode1, website.StatusCode)
			}
		} else if Config.CLDiff != 0 && success != "" && sameBodyLength && len(body) > 0 && compareLengths(len(body), len(website.Body), Config.CLDiff) {
			if !recursive {
				var tmpWebsite WebsiteStruct
				var err error

				count := 3
				for i := 0; i < count; i++ {
					tmpWebsite, err = GetWebsite(Config.Website.Url.String(), true, true)
					if err == nil {
						break
					}
				}
				if err != nil {
					repResult.HasError = true
					msg := fmt.Sprintf("%s: couldn't verify if body length %d is the new default body length, because the verification request encountered the following error %d times: %s", request.URL, statusCode1, count, err.Error())
					repResult.ErrorMessages = append(repResult.ErrorMessages, msg)
				} else {
					Config.Website = tmpWebsite
				}
				return checkPoisoningIndicators(repResult, request, success, body, poison, statusCode1, statusCode2, sameBodyLength, header, true)
			} else {
				request.Reason = fmt.Sprintf("Length %d differed more than %d bytes from normal length %d", len(body), Config.CLDiff, len(website.Body))
			}
		} else {
			return testForResponseSplitting
		}
	}

	PrintNewLine()
	Print(success, Green)
	msg := "URL: " + request.URL + "\n"
	Print(msg, Green)
	msg = "Reason: " + request.Reason + "\n\n"
	Print(msg, Green)
	repResult.Vulnerable = true
	repResult.Requests = append(repResult.Requests, request)
	return testForResponseSplitting
}

func compareLengths(len1 int, len2 int, limit int) bool {

	var diff int
	if len1 >= len2 {
		diff = len1 - len2
	} else {
		diff = len2 - len1
	}

	return diff > limit
}

/* Check if the second response makes sense or the continuation shall be stopped */
func stopContinuation(body []byte, statusCode int, headers http.Header) bool {
	if string(body) != Config.Website.Body {
		return false
	} else if statusCode != Config.Website.StatusCode {
		return false
	} else if len(headers) != len(Config.Website.Headers) {
		return false
	}

	for k, v := range headers {
		v2 := Config.Website.Headers.Values(k)

		// check if length of v and v2 is the same
		if len(v) != len(v2) {
			return false
		}
	}
	return true
}

func addParameters(urlStr *string, parameters []string) {
	for _, p := range parameters {
		if p == "" {
			continue
		}
		if !strings.Contains(*urlStr, "?") {
			*urlStr += "?"
		} else {
			*urlStr += Config.QuerySeperator
		}
		*urlStr += p
	}
}

func firstRequest(rp requestParams) ([]byte, int, reportRequest, http.Header, error) {
	var req *http.Request
	var resp *http.Response
	var err error
	var msg string
	var body []byte
	var repRequest reportRequest

	if rp.headers == nil {
		rp.headers = []string{""}
	}
	if rp.values == nil {
		rp.values = []string{""}
	}
	if rp.parameters == nil {
		rp.parameters = []string{""}
	}

	if rp.values[0] == "2ndrequest" {
		rp.identifier = fmt.Sprintf("2nd request of %s", rp.identifier)
	} else {
		rp.identifier = fmt.Sprintf("1st request of %s", rp.identifier)
	}

	// check if headers and values have the same length
	if len(rp.headers) != len(rp.values) && rp.values[0] != "2ndrequest" {
		msg = fmt.Sprintf("%s: len(header) %s %d != len(value) %s %d\n", rp.identifier, rp.headers, len(rp.headers), rp.values, len(rp.values))
		Print(msg, Red)
		return body, -1, repRequest, nil, errors.New(msg)
	}

	addParameters(&rp.url, rp.parameters)

	if !rp.forcePost && Config.Website.Cache.CBisHTTPMethod && rp.values[0] != "2ndrequest" {
		req, err = http.NewRequest(Config.Website.Cache.CBName, rp.url, bytes.NewBufferString(rp.bodyString))
	} else if Config.DoPost || rp.forcePost {
		if rp.bodyString == "" {
			rp.bodyString = Config.Body
		}
		req, err = http.NewRequest("POST", rp.url, bytes.NewBufferString(rp.bodyString))
	} else if rp.bodyString != "" {
		req, err = http.NewRequest("GET", rp.url, bytes.NewBufferString(rp.bodyString))
	} else {
		req, err = http.NewRequest("GET", rp.url, nil)
	}
	if err != nil {
		msg = fmt.Sprintf("%s: http.NewRequest: %s\n", rp.identifier, err.Error())
		Print(msg, Red)
		return body, -1, repRequest, nil, errors.New(msg)
	}

	newClient := http.Client{
		CheckRedirect: http.DefaultClient.CheckRedirect,
		Timeout:       http.DefaultClient.Timeout,
	}

	setRequest(req, Config.DoPost, rp.cb, rp.newCookie)

	for i := range rp.headers {
		if rp.headers[i] == "" {
			continue
		}
		if rp.values[0] == "2ndrequest" {
			msg = rp.identifier + "2nd request doesnt allow headers to be set\n"
			Print(msg, Red)
			break
		}
		if strings.EqualFold(rp.headers[i], "Host") && !rp.duplicateHeaders {
			newHost := req.URL.Host + rp.values[i]
			msg := fmt.Sprintf("Overwriting Host:%s with Host:%s\n", req.URL.Host, newHost)
			PrintVerbose(msg, NoColor, 2)
			req.Host = newHost
		} else if rp.headers[i] != "" {
			if h := req.Header.Get(rp.headers[i]); h != "" && !rp.duplicateHeaders {
				msg := fmt.Sprintf("Overwriting %s:%s with %s:%s\n", rp.headers[i], h, rp.headers[i], rp.values[i])
				PrintVerbose(msg, NoColor, 2)
				// Directly writing to map doesn't uppercase header(for HTTP1)
				req.Header[rp.headers[i]] = []string{rp.values[i]}
			} else if h != "" && rp.duplicateHeaders {
				// Directly writing to map doesn't uppercase the header(for HTTP1)
				req.Header[rp.headers[i]] = []string{h, rp.values[i]}
			} else {
				// Directly writing to map doesn't uppercase the header(for HTTP1)
				req.Header[rp.headers[i]] = []string{rp.values[i]}
			}
		}
	}

	waitLimiter(rp.identifier)
	resp, err = newClient.Do(req)

	if err != nil {
		msg = fmt.Sprintf("%s: newClient.Do: %s\n", rp.identifier, err.Error())
		Print(msg, Red)
		return body, -1, repRequest, nil, errors.New(msg)
	} else {
		defer resp.Body.Close()

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			msg = fmt.Sprintf("%s: ioutil.ReadAll: %s\n", rp.identifier, err.Error())
			Print(msg, Red)
			return body, -1, repRequest, nil, errors.New(msg)
		}

		if resp.StatusCode != Config.Website.StatusCode {
			msg = fmt.Sprintf("Unexpected Status Code %d for %s\n", resp.StatusCode, rp.identifier)
			Print(msg, Yellow)
		}
	}
	if stopContinuation(body, resp.StatusCode, resp.Header.Clone()) {
		msg := "stop"
		return body, -1, repRequest, nil, errors.New(msg)
	}

	requestBytes, _ := httputil.DumpRequestOut(req, true)
	repRequest.Request = string(requestBytes)

	responseBytes, _ := httputil.DumpResponse(resp, true)
	repRequest.Response = string(responseBytes)

	repRequest.URL = req.URL.String()

	//TODO: Also use dumped request/response of 2nd request

	return body, resp.StatusCode, repRequest, resp.Header.Clone(), nil
}

func secondRequest(rUrl string, identifier string, cb string) ([]byte, int, http.Header, error) {
	rp := requestParams{
		values:     []string{"2ndrequest"},
		identifier: identifier,
		url:        rUrl,
		cb:         cb,
	}

	body, statusCode, _, header, err := firstRequest(rp)

	return body, statusCode, header, err
}

// TODO: ResponseSplitting Methode
/* return value:first bool is needed for responsesplitting, second bool is only needed for ScanParameters */
func issueRequest(rp requestParams) (bool, bool) {
	body1, statusCode1, request, header1, err := firstRequest(rp)
	if err != nil {
		if err.Error() != "stop" {
			if rp.m != nil {
				rp.m.Lock()
				defer rp.m.Unlock()
			}
			rp.repResult.HasError = true
			rp.repResult.ErrorMessages = append(rp.repResult.ErrorMessages, err.Error())
		}

		return false, false
	}

	firstRequestPoisoningIndicator(rp.identifier, body1, rp.poison, header1)

	body2, statusCode2, respHeader, err := secondRequest(rp.url, rp.identifier, rp.cb)
	if err != nil {
		if err.Error() != "stop" {
			if rp.m != nil {
				rp.m.Lock()
				defer rp.m.Unlock()
			}
			rp.repResult.HasError = true
			rp.repResult.ErrorMessages = append(rp.repResult.ErrorMessages, err.Error())
		}
		return false, true
	}
	sameBodyLength := len(body1) == len(body2)

	// Lock here, to prevent false positives and too many GetWebsite requests

	if rp.m != nil {
		rp.m.Lock()
		defer rp.m.Unlock()
	}
	responseSplitting := checkPoisoningIndicators(rp.repResult, request, rp.success, string(body2), rp.poison, statusCode1, statusCode2, sameBodyLength, respHeader, false)

	return responseSplitting, true
}

func firstRequestPoisoningIndicator(identifier string, body []byte, poison string, header http.Header) {
	var reason string
	if poison != "" && strings.Contains(string(body), poison) {
		reason = "Response Body contained " + poison
	}
	if header != nil && poison != "" {
		for x := range header {
			if strings.Contains(header.Get(x), poison) {
				reason = "Response Body contained " + poison
			}
		}
	}
	if Config.CLDiff != 0 && reason == "" && len(body) > 0 && compareLengths(len(body), len(Config.Website.Body), Config.CLDiff) {
		reason = fmt.Sprintf("Length %d differed more than %d bytes from normal length %d", len(body), Config.CLDiff, len(Config.Website.Body))
	}

	if reason != "" {
		msg := identifier + ": " + reason + "\n"
		Print(msg, Cyan)
	}

}
