package pkg

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

var impactfulQueries []string

func init() {
}

/* Scan cookies for poisoning */
func ScanCookies() reportResult {
	var repResult reportResult
	repResult.Technique = "Cookies"
	for i, c := range Config.Website.Cookies {

		poison := randInt()
		msg := fmt.Sprintf("Checking cookie %s (%d/%d)\n", c.Name, i+1, len(Config.Website.Cookies))
		Print(msg, NoColor)

		rUrl := Config.Website.Url.String()
		cb := randInt()
		success := fmt.Sprintf("Cookie %s was successfully poisoned! cb: %s poison: %s\n", c.Name, cb, poison)
		identifier := c.Name + "=" + c.Value
		msg = fmt.Sprintf("Overwriting %s=%s with %s=%s\n", c.Name, c.Value, c.Name, poison)
		Print(msg, NoColor)

		newCookie := *c
		newCookie.Value = poison

		rp := requestParams{
			repResult:        &repResult,
			headers:          []string{""},
			values:           []string{""},
			identifier:       identifier,
			poison:           poison,
			url:              rUrl,
			cb:               cb,
			success:          success,
			bodyString:       "",
			forcePost:        false,
			duplicateHeaders: false,
			m:                nil,
			newCookie:        newCookie,
		}
		responseSplitting, _ := issueRequest(rp)

		// check for response splitting, if poison was reflected in a header
		if responseSplitting {
			msg := fmt.Sprintf("Checking cookie %s for Response Splitting, because it was reflected in the response' header\n", c.Name)
			PrintVerbose(msg, Cyan, 1)

			rp.poison += getRespSplit()
			rp.url = rUrl
			rp.cb = randInt()
			rp.success = fmt.Sprintf("Cookie %s was successfully poisoned with Response Splitting! cb: %s poison: %s\n", c.Name, rp.cb, rp.poison)
			rp.identifier += " response splitting"

			msg = fmt.Sprintf("Overwriting %s=%s with %s=%s\n", c.Name, c.Value, c.Name, rp.poison)
			Print(msg, NoColor)

			issueRequest(rp)
		}
	}
	return repResult
}

func ScanForwardingHeaders() reportResult {
	var repResult reportResult
	repResult.Technique = "Forward/Host Headers"

	// Host header
	header := "Host"

	portInt := 31337
	// Check if port is already contained in default response
	for searchBodyHeadersForString(strconv.Itoa(portInt), Config.Website.Body, Config.Website.Headers) {
		portInt++
	}
	port := strconv.Itoa(portInt)

	values := []string{":" + port, ":@" + port, " " + port}
	for _, value := range values {
		PrintVerbose("Port-Number "+strconv.Itoa(portInt)+" was already present in websites response. Adding 1 to it.\n", NoColor, 2)
		ForwardHeadersTemplate(&repResult, []string{header}, []string{value}, header, value, false)
	}

	// Duplicate Host header
	header = "host"
	poison := randInt()
	values = []string{poison}
	for _, value := range values {
		ForwardHeadersTemplate(&repResult, []string{header}, []string{value}, header, value, true)
	}

	// X-Forwarded Headers
	headers := []string{"X-Forwarded-Host", "X-Forwarded-Scheme"}
	poison = randInt()
	values = []string{poison, "nothttps"}
	identifier := "X-Forwarded-Host and X-Forwarded-Scheme"
	ForwardHeadersTemplate(&repResult, headers, values, identifier, poison, false)

	// Forwarded Header
	header = "Forwarded"
	value := "host=" + randInt()
	ForwardHeadersTemplate(&repResult, []string{header}, []string{value}, header, value, false)

	// X-Forwarded-Port Header
	header = "X-Forwarded-Port"
	value = port
	ForwardHeadersTemplate(&repResult, []string{header}, []string{value}, header, value, false)

	return repResult
}

func ForwardHeadersTemplate(repResult *reportResult, headers []string, values []string, identifier string, poison string, duplicateHeaders bool) {
	rUrl := Config.Website.Url.String()
	cb := randInt()
	success := fmt.Sprintf("%s was successfully poisoned! cb: %s poison: %s\n", headers, cb, values)

	rp := requestParams{
		repResult:        repResult,
		headers:          headers,
		values:           values,
		identifier:       identifier,
		poison:           poison,
		url:              rUrl,
		cb:               cb,
		success:          success,
		bodyString:       "",
		forcePost:        false,
		duplicateHeaders: duplicateHeaders,
		m:                nil,
		newCookie:        http.Cookie{},
	}
	responseSplitting, _ := issueRequest(rp)

	// check for response splitting, if poison was reflected in a header
	if responseSplitting {
		rp.values[0] += getRespSplit()
		msg := fmt.Sprintf("Checking header(s) %s with value(s) %s for Response Splitting, because it was reflected in the response' header\n", rp.headers, rp.values)
		PrintVerbose(msg, Cyan, 1)

		rp.poison += getRespSplit()
		rp.url = rUrl
		rp.cb = randInt()
		rp.success = fmt.Sprintf("%s was successfully poisoned with Response Splitting! cb: %s poison: %s\n", headers, rp.cb, rp.values)
		rp.identifier += " response splitting"

		issueRequest(rp)
	}
}

func ScanHTTPRequestSmuggling(proxyURL *url.URL) reportResult {
	var repResult reportResult
	identifier := "HTTP Request Smuggling"
	repResult.Technique = identifier

	path := Config.Website.Url.Path
	if Config.Website.Cache.CBisParameter {
		path, _ = addCachebusterParameter(path, "")
	}
	if path == "" {
		path = "/"
	}
	headers := GenerateHeaderString()

	PrintVerbose("Trying CLTE Request Smuggling\n", NoColor, 1)
	req := clte(path, headers)
	httpRequestSmuggling(req, &repResult, proxyURL)

	if !repResult.Vulnerable {
		PrintVerbose("Trying TECL Request Smuggling\n", NoColor, 1)
		req = tecl(path, headers)
		httpRequestSmuggling(req, &repResult, proxyURL)
	}

	if !repResult.Vulnerable {
		PrintVerbose("Trying CLCL Request Smuggling\n", NoColor, 1)
		req = clcl(path, headers)
		httpRequestSmuggling(req, &repResult, proxyURL)
	}

	if !repResult.Vulnerable {
		PrintVerbose("Trying CLCL2 Request Smuggling\n", NoColor, 1)
		req = clcl2(path, headers)
		httpRequestSmuggling(req, &repResult, proxyURL)
	}

	return repResult
}

/* Scan headers for poisoning */
func ScanHeaders(headerList []string) reportResult {
	var repResult reportResult
	repResult.Technique = "Headers"

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(headerList))
	var m sync.Mutex

	msg := fmt.Sprintf("Testing %d headers\n", len(headerList))
	PrintVerbose(msg, NoColor, 1)

	for i, header := range headerList {
		header = strings.Trim(header, "\r")
		if header == "" {
			msg := fmt.Sprintf("Skipping empty header (%d/%d)\n", i+1, len(headerList))
			PrintVerbose(msg, NoColor, 1)

			wg.Done()
			continue
		}

		header = http.CanonicalHeaderKey(header)

		go func(i int, header string) {
			defer wg.Done()
			sem <- 1

			//msg := fmt.Sprintf("Testing now (%d/%d) %s\n", i+1, len(headerList), header)
			//PrintVerbose(msg, NoColor, 2)
			rUrl := Config.Website.Url.String()
			poison := randInt()
			cb := randInt()
			success := fmt.Sprintf("Header %s was successfully poisoned! cb: %s poison: %s\n", header, cb, poison)
			identifier := fmt.Sprintf("header %s", header)

			rp := requestParams{
				repResult:        &repResult,
				headers:          []string{header},
				values:           []string{poison},
				identifier:       identifier,
				poison:           poison,
				url:              rUrl,
				cb:               cb,
				success:          success,
				bodyString:       "",
				forcePost:        false,
				duplicateHeaders: false,
				m:                &m,
				newCookie:        http.Cookie{},
			}
			responseSplitting, _ := issueRequest(rp)

			// check for response splitting, if poison was reflected in a header
			if responseSplitting {
				msg := fmt.Sprintf("Testing now (%d/%d) %s for Response Splitting, because it was reflected in the response' header\n", i+1, len(headerList), header)
				PrintVerbose(msg, Cyan, 1)

				rp.url = rUrl
				rp.cb = randInt()
				rp.poison += getRespSplit()
				rp.success = fmt.Sprintf("Header %s was successfully poisoned with Response Splitting! cb: %s poison: %s\n", header, rp.cb, rp.poison)
				rp.identifier += " response splitting"

				issueRequest(rp)
			}

			<-sem
		}(i, header)

	}
	wg.Wait()

	return repResult
}

/* Scan headers for poisoning. Test 10x aufeinmal */ /*
func ScanHeaders(headerList []string) reportResult {
	var repResult reportResult
	repResult.Technique = "Headers"

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(headerList))
	var m sync.Mutex

	// add 10 headers at a time to check if the reponse differs
	for i := 0; i < len(headerList); i += 10 {
		var headers = []string{}
		for ii := 0; i < 10; i++ {
			if len(headerList) > i+ii {
				defer wg.Done()

				headerToAdd := strings.Trim(headerList[i+ii], "\r")
				if headerToAdd == "" {
					msg := fmt.Sprintf("Skipping empty header (%d/%d)\n", i+1, len(headerList))
					PrintVerbose(msg, NoColor, 1)

					wg.Done()
					continue
				} else {
					headerToAdd = http.CanonicalHeaderKey(headerToAdd)
					headers = append(headers, headerToAdd)
				}
			}
		}

		poison := randInt()

		msg := fmt.Sprintf("Testing now (%d/%d) %s\n", i+ii+1, len(headerList), headers)
		PrintVerbose(msg, NoColor, 2)
		urlWithCb, _ := addCacheBuster(Config.Website.Url.String(), "", Config.CacheBuster)

		identifier := fmt.Sprintf("headers %s", headers)

		rp := requestParams{
			headers:    headers,
			values:     []string{poison},
			identifier: identifier,
			poison:     poison,
			url:        urlWithCb,
		}
		respBody, respCode, _, respHeaders, err := firstRequest(rp)
		// TODO repeat when timedout
		if err != nil {
			continue
		}

		for ii, header := range headers {
			poison = randInt()

			go func(i int, header string, poison string) {
				defer wg.Done()
				sem <- 1

				msg := fmt.Sprintf("Testing now (%d/%d) %s\n", i+1, len(headerList), header)
				PrintVerbose(msg, NoColor, 2)
				urlWithCb, cb := addCacheBuster(Config.Website.Url.String(), "", Config.CacheBuster)
				success := fmt.Sprintf("Header %s was successfully poisoned! cb: %s poison: %s\n", header, cb, poison)
				identifier := fmt.Sprintf("header %s", header)

				rp := requestParams{
					repResult:        &repResult,
					headers:          []string{header},
					values:           []string{poison},
					identifier:       identifier,
					poison:           poison,
					url:              urlWithCb,
					cb:               cb,
					success:          success,
					bodyString:       "",
					forcePost:        false,
					duplicateHeaders: false,
					m:                &m,
					cookie:           oldCookie{},
				}
				responseSplitting, _ := issueRequest(rp)

				// check for response splitting, if poison was reflected in a header
				if responseSplitting {
					msg := fmt.Sprintf("Testing now (%d/%d) %s for Response Splitting, because it was reflected in the response' header\n", i+1, len(headerList), header)
					PrintVerbose(msg, Cyan, 1)

					rp.url, rp.cb = addCacheBuster(Config.Website.Url.String(), "", Config.CacheBuster)
					rp.poison += getRespSplit()
					rp.success = fmt.Sprintf("Header %s was successfully poisoned with Response Splitting! cb: %s poison: %s\n", header, rp.cb, rp.poison)
					rp.identifier += " response splitting"

					issueRequest(rp)
				}

				<-sem
			}(i+ii, header, poison)
		}

	}
	wg.Wait()

	return repResult
}*/

/*
func addCbWithPoison(parameter string, poison string) (string, string) {
	var urlWithCb, cb string
	if _, ok := Config.Website.Queries[parameter]; ok {
		// if the query to add is already present
		queryParameterMap := make(map[string]string)

		for key, val := range Config.Website.Queries {
			queryParameterMap[key] = val
		}

		msg := fmt.Sprintf("Overwriting %s=%s with %s=%s\n", parameter, queryParameterMap[parameter], parameter, poison)
		Print(msg, NoColor)
		queryParameterMap[parameter] = poison

		urlWithCb = Config.Website.UrlWOQueries + "?"
		for key, val := range queryParameterMap {
			if !strings.HasSuffix(urlWithCb, "?") {
				urlWithCb += "&"
			}
			urlWithCb += key + "=" + val
		}

		urlWithCb, cb = AddCacheBuster(urlWithCb+Config.QuerySeperator, "", Config.CacheBuster)
	} else {
		// if query isn't already present, just add it and the cachebuster
		urlWithCb = Config.Website.Url.String()
		urlWithCb += parameter + "=" + poison + Config.QuerySeperator
		urlWithCb, cb = AddCacheBuster(urlWithCb, "", Config.CacheBuster)
	}

	return urlWithCb, cb
}
*/

/* Scan query parameters for poisoning */
func ScanParameters(parameterList []string) reportResult {
	var repResult reportResult
	repResult.Technique = "Parameters"

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(parameterList))
	var m sync.Mutex

	impactfulQueries = nil

	msg := fmt.Sprintf("Testing %d parameters\n", len(parameterList))
	PrintVerbose(msg, NoColor, 1)

	for i, parameter := range parameterList {
		if parameter == "" {
			msg := fmt.Sprintf("Skipping empty query (%d/%d) %s\n", i+1, len(parameterList), parameter)
			PrintVerbose(msg, NoColor, 2)
			wg.Done()
			continue
		}

		go func(i int, parameter string) {
			defer wg.Done()
			sem <- 1

			parameter = strings.Trim(parameter, "\r")
			//msg := fmt.Sprintf("Testing now Parameter (%d/%d) %s\n", i+1, len(parameterList), parameter)
			//PrintVerbose(msg, NoColor, 2)

			rUrl := Config.Website.Url.String()
			poison := randInt()
			cb := randInt()
			success := fmt.Sprintf("Query Parameter %s was successfully poisoned! cb: %s poison: %s\n", parameter, cb, poison)
			identifier := fmt.Sprintf("parameter %s", parameter)

			rp := requestParams{
				repResult:        &repResult,
				headers:          []string{""},
				values:           []string{poison},
				parameters:       []string{parameter + "=" + poison},
				identifier:       identifier,
				poison:           poison,
				url:              rUrl,
				cb:               cb,
				success:          success,
				bodyString:       "",
				forcePost:        false,
				duplicateHeaders: false,
				newCookie:        http.Cookie{},
				m:                &m,
			}
			responseSplitting, appendParameter := issueRequest(rp)

			if appendParameter {
				impactfulQueries = append(impactfulQueries, parameter)
			}
			// check for response splitting, if poison was reflected in a header
			if responseSplitting {
				msg := fmt.Sprintf("Testing now Parameter (%d/%d) %s for Response Splitting, because it was reflected in the response' header\n", i+1, len(parameterList), parameter)
				PrintVerbose(msg, Cyan, 1)

				rp.poison += getRespSplit()
				rp.parameters = []string{parameter + "=" + rp.poison}
				rp.url = rUrl
				rp.cb = randInt()
				rp.success = fmt.Sprintf("Query Parameter %s was successfully poisoned with Response Splitting! cb: %s poison: %s\n", parameter, rp.cb, rp.poison)
				rp.identifier += " response splitting"
				issueRequest(rp)
			}

			<-sem
		}(i, parameter)

	}
	wg.Wait()

	return repResult
}

/* Check for fat GET */
func ScanFatGET() reportResult {
	var repResult reportResult
	repResult.Technique = "Fat GET"

	if len(impactfulQueries) == 0 {
		msg := "No impactful query parameters were found beforehand. Run the query parameter scan (maybe with a different wordlist)."
		Print(msg+"\n", Yellow)
		repResult.HasError = true
		repResult.ErrorMessages = append(repResult.ErrorMessages, msg)
		return repResult
	} else {
		msg := fmt.Sprintf("The following parameters were found to be impactful and will be tested for parameter cloaking: %s\n", impactfulQueries)
		Print(msg, NoColor)
	}

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(impactfulQueries))
	var m sync.Mutex

	headers := []string{"", "", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}
	values := []string{"", "", "POST", "POST", "POST"}

	for method := 0; method < 5; method++ {
		var identifier string
		forcePost := false
		if method == 0 {
			identifier = "simple Fat GET"
		} else if method == 1 {
			identifier = "POST Fat GET"
			forcePost = true
		} else {
			identifier = fmt.Sprintf("%s Fat GET", headers[method-2])
		}
		msg := "Testing now " + identifier + "\n"
		Print(msg, NoColor)

		for i, s := range impactfulQueries {
			// Parameter Limit for BA
			if i >= 500 {
				if i == 500 {
					Print("Parameter Limit for BA at 500\n", Red)
				}
				wg.Done()
				continue
			}
			poison := randInt()

			go func(i int, s string, poison string) {
				defer wg.Done()
				sem <- 1

				msg := fmt.Sprintf("(%d/%d) %s\n", i+1, len(impactfulQueries), s)
				PrintVerbose(msg, NoColor, 2)
				rUrl := Config.Website.Url.String()
				cb := randInt()
				bodyString := s + "=" + poison
				success := fmt.Sprintf("Query Parameter %s was successfully poisoned via %s! cb: %s poison:%s\n", s, identifier, cb, poison)

				rp := requestParams{
					repResult:        &repResult,
					headers:          []string{headers[method]},
					values:           []string{values[method]},
					identifier:       identifier,
					poison:           poison,
					url:              rUrl,
					cb:               cb,
					success:          success,
					bodyString:       bodyString,
					forcePost:        forcePost,
					duplicateHeaders: false,
					m:                &m,
					newCookie:        http.Cookie{},
				}
				responseSplitting, _ := issueRequest(rp)

				// check for response splitting, if poison was reflected in a header
				if responseSplitting {
					msg := fmt.Sprintf("Testing now (%d/%d) %s for Response Splitting, because it was reflected in the response' header\n", i+1, len(impactfulQueries), s)
					PrintVerbose(msg, Cyan, 1)

					rp.url = rUrl
					rp.cb = randInt()
					rp.poison += getRespSplit()
					rp.bodyString += getRespSplit()
					rp.identifier += " response splitting"
					rp.success = fmt.Sprintf("Query Parameter %s was successfully poisoned via %s with Response Splitting! cb: %s poison:%s\n", s, identifier, rp.cb, rp.poison)

					issueRequest(rp)
				}

				<-sem
			}(i, s, poison)
		}
		wg.Wait()
		wg.Add(len(impactfulQueries))
	}

	return repResult
}

/* Check for Parameter Cloaking */
func ScanParameterCloaking() reportResult {
	var repResult reportResult
	repResult.Technique = "Parameter Cloaking"

	if len(impactfulQueries) == 0 {
		msg := "No impactful query parameters were found beforehand. Run the query parameter scan (maybe with a different wordlist)."
		Print(msg+"\n", Yellow)
		repResult.HasError = true
		repResult.ErrorMessages = append(repResult.ErrorMessages, msg)
		return repResult
	} else {
		msg := fmt.Sprintf("The following parameters were found to be impactful and will be tested for parameter cloaking:\n%s\n", impactfulQueries)
		Print(msg, NoColor)
	}

	utm_parameter := []string{"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term"}
	unkeyed_parameter := []string{}

	/***********Check if urlWithCb already contains utm parameter.
				Check if ? or querySeperator is needed
	****************/

	// The first request is made so a cache miss is forced and the following responses will only
	//have a cache hit, if they are unkeyed
	rUrl := Config.Website.Url.String()
	cb := randInt()
	rp := requestParams{
		identifier: "first request %s",
		url:        rUrl,
		cb:         cb,
	}
	firstRequest(rp)

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	var m sync.Mutex
	cache := Config.Website.Cache
	if cache.Indicator == "" /*|| cache.TimeIndicator*/ {
		//Add tests for cache.TimeIndicator and cache.Reflection
		//Cant test if utm_parameter are unkeyed if X-Cache isn't set
		//So they will be all added as unkeyed_parameter
		msg := "hit/miss isn't verbose. Can't check which utm_parameter is unkeyed, so all will be used\n"
		Print(msg, Yellow)
		unkeyed_parameter = utm_parameter
	} else {
		//Test which utm_parameter are unkeyed
		wg.Add(len(utm_parameter))

		for i, s := range utm_parameter {
			// Parameter Limit for BA
			if i >= 500 {
				if i == 500 {
					Print("Parameter Limit for BA at 500\n", Red)
				}
				wg.Done()
				continue
			}
			go func(i int, s string) {
				defer wg.Done()
				sem <- 1

				msg := fmt.Sprintf("Testing now for unkeyed utm parameters (%d/%d) %s\n", i+1, len(utm_parameter), s)
				PrintVerbose(msg, NoColor, 2)

				identifier := fmt.Sprintf("unkeyed utm %s", s)
				//TODO: TimeOut behandeln!!!
				rp := requestParams{
					identifier: identifier,
					url:        rUrl,
					cb:         cb,
					parameters: []string{s + "=foobar"}, // utm parameter with nonsense value
				}
				_, _, _, respHeader, err := firstRequest(rp)
				if err != nil {
					if err.Error() == "stop" {
						return
					}
					m.Lock()
					repResult.HasError = true
					repResult.ErrorMessages = append(repResult.ErrorMessages, err.Error())
					m.Unlock()
				}
				indicValue := respHeader.Get(cache.Indicator)
				if checkCacheHit(indicValue) {
					m.Lock()
					unkeyed_parameter = append(unkeyed_parameter, s)
					m.Unlock()
				}
			}(i, s)
		}
		wg.Wait()
	}

	if len(unkeyed_parameter) == 0 {
		msg := "No unkeyed utm parameters could be found. Parameter Cloaking is not possible using utm parameters\n"
		Print(msg, Yellow)
	} else {
		msg := fmt.Sprintf("The following utm parameters were found to be unkeyed and will be tested for parameter cloaking:\n %s\n", unkeyed_parameter)
		Print(msg, NoColor)
	}

	cloak := ";"
	if Config.QuerySeperator == ";" {
		cloak = "&"
	}

	for iu, u := range unkeyed_parameter {

		//its sufficient to only test one unkeyed_parameter as it should behave the same way as the others.
		if iu > 0 && cache.Indicator != "" {
			break
		}
		wg.Add(len(impactfulQueries))

		for is, s := range impactfulQueries {

			poison := randInt()

			go func(iu int, u string, is int, s string, poison string) {
				defer wg.Done()
				sem <- 1

				msg := fmt.Sprintf("Testing now Parameter Cloaking (%d/%d) %s%s%s\n", iu+is+1, len(impactfulQueries)*len(unkeyed_parameter), u, cloak, s)
				PrintVerbose(msg, NoColor, 2)
				cb := randInt()
				success := fmt.Sprintf("Query Parameter %s was successfully poisoned via Parameter Cloaking using %s! cb:%s poison:%s\n", s, u, cb, poison)
				identifier := fmt.Sprintf("parameter cloaking %s %s", u, s)

				rp := requestParams{
					repResult:        &repResult,
					headers:          []string{""},
					values:           []string{poison},
					parameters:       []string{u + "=foobar" + cloak + s + "=" + poison},
					identifier:       identifier,
					poison:           poison,
					url:              rUrl,
					cb:               cb,
					success:          success,
					bodyString:       "",
					forcePost:        false,
					duplicateHeaders: false,
					m:                &m,
					newCookie:        http.Cookie{},
				}
				responseSplitting, _ := issueRequest(rp)

				// check for response splitting, if poison was reflected in a header
				if responseSplitting {
					msg := fmt.Sprintf("Testing now Parameter Cloaking (%d/%d) %s%s%s for Response Splitting, because it was reflected in the response' header\n", iu+is+1, len(impactfulQueries)*len(unkeyed_parameter), u, cloak, s)
					PrintVerbose(msg, Cyan, 1)

					rp.url = rUrl
					rp.cb = randInt()
					rp.poison += getRespSplit()
					rp.parameters = []string{u + "=foobar" + cloak + s + "=" + rp.poison}
					rp.success = fmt.Sprintf("Query Parameter %s was successfully poisoned via Response Splitting using %s with Parameter Cloaking! cb:%s poison:%s\n", s, u, rp.cb, rp.poison)
					rp.identifier += " response splitting"

					issueRequest(rp)
				}

				<-sem
			}(iu, u, is, s, poison)
		}
		wg.Wait()
	}

	return repResult
}

/* Check for different DOS techniques */
func DOS() reportResult {
	var repResult reportResult
	repResult.Technique = "DOS"

	// TODO: Ist nur Header Value oder auch Header Name ausschlaggebend?
	hho(&repResult)

	// HMC (Header Metachar Character)
	// TODO: Check for more META CHARACTERS?
	//TODO: Change to other header, which is probably whitelisted
	headers := []string{"X-Metachar-Header"}
	values := []string{"\\n", "\\r", "\\a", "\\0", "\\b", "\\e", "\\v", "\\f", "\\u0000"}

	for _, header := range headers {
		headerDOSTemplate(&repResult, values, header, "HMC ", true)
	}

	// HMO (HTTP Method Override)
	values = []string{"GET", "POST", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "PUT", "TRACE", "NONSENSE"}
	headers = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}
	for _, header := range headers {
		headerDOSTemplate(&repResult, values, header, "HMO ", true)
	}

	// DOS via not implemented transferEncoding
	values = []string{"asdf"}
	headerDOSTemplate(&repResult, values, "zTRANSFER-ENCODING", "Not supported Transfer-Encoding ", true)

	// DOS via incompatible/outdated browser agent
	values = []string{"Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))"}
	headerDOSTemplate(&repResult, values, "User-Agent", "incompatible browser ", true)

	// DOS via blacklisted security scanner user agent // TODO: Also add bots? Or will the IP be blocked too fast
	values = []string{UserAgent + " v" + version, "Fuzz Faster U Fool", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "sqlmap/1.3.11#stable (http://sqlmap.org)", "gobuster/3.1.0", "Wfuzz/2.2", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "masscan/1.3", "blekkobot"}
	headerDOSTemplate(&repResult, values, "User-Agent", "blacklisted security scanners ", true)

	// DOS via illegal header name
	/* Currently disabled because of net/http throws error because of illegal character TODO: workaround, see https://stackoverflow.com/questions/70678016/how-to-bypass-golangs-http-request-net-http-rfc-compliance
	values = []string{"foobar"}
	headerDOSTemplate(&repResult, values, "Ill\\egal", "illegal header name ", true)
	*/

	// DOS via Max-Forwards (Webserver/Cache returns request)
	values = []string{"0", "1", "2"}
	headerDOSTemplate(&repResult, values, "Max-Forwards", "max-forwards ", true)

	// DOS via waf blocking because of a blacklist word
	// TODO: change header to probably whitelisted header, More Blacklist words?
	values = []string{".burpcollaborator.net", "<script>alert(1)</script>"}
	headerDOSTemplate(&repResult, values, "Any-Header", "blacklist ", true)

	// DOS via Range
	values = []string{"bytes=cow"}
	headerDOSTemplate(&repResult, values, "Range", "", true)

	// DOS via X-Forwarded-Protocol
	values = []string{"http", "https", "ssl", "nonsense"}
	headerDOSTemplate(&repResult, values, "X-Forwarded-Protocol", "", true)

	// DOS via X-Forwarded-Protocol
	values = []string{"http", "https", "nothttps", "nonsense"}
	headerDOSTemplate(&repResult, values, "X-Forwarded-Scheme", "", true)

	// DOS via X-Fordwarded-SSL
	values = []string{"on", "off", "nonsense"}
	headerDOSTemplate(&repResult, values, "X-Forwarded-SSL", "", true)

	return repResult
}

/* HTTP Header Oversize */
func hho(repResult *reportResult) {
	repetitions := []int{50, 100, 200} //4k, 8k, 16k

	msg := fmt.Sprintf("Testing now HHO with Size Limits of ~80*%d bytes\n", repetitions)
	PrintVerbose(msg, NoColor, 2)

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(repetitions))
	var m sync.Mutex

	for _, repetition := range repetitions {
		go func(repetition int) {
			defer wg.Done()
			sem <- 1

			limit := repetition * 8 / 100
			//msg := fmt.Sprintf("Testing now HHO with Size Limit %dk bytes\n", limit)
			//Print(msg, NoColor)

			headers := []string{}
			values := []string{}

			for i := 0; i < repetition; i++ {
				headername := fmt.Sprintf("X-Oversized-Header-%d", i+1)
				value := "Big-Value-000000000000000000000000000000000000000000000000000000000000000000000000000000"
				headers = append(headers, headername)
				values = append(values, value)
			}

			rUrl := Config.Website.Url.String()
			cb := randInt()
			identifier := fmt.Sprintf("HHO with limit of %dk bytes", limit)
			rp := requestParams{
				headers:    headers,
				values:     values,
				identifier: identifier,
				url:        rUrl,
				cb:         cb,
			}
			_, statusCode1, request, _, err := firstRequest(rp)
			if err != nil {
				if err.Error() != "stop" {
					m.Lock()
					repResult.HasError = true
					repResult.ErrorMessages = append(repResult.ErrorMessages, err.Error())
					m.Unlock()
				}
				return
			}

			// send second request also with cb
			_, statusCode2, respHeader, err := secondRequest(rUrl, identifier, cb)
			if err != nil {
				if err.Error() != "stop" {
					m.Lock()
					repResult.HasError = true
					repResult.ErrorMessages = append(repResult.ErrorMessages, err.Error())
					m.Unlock()
				}
				return
			}

			msg = fmt.Sprintf("HHO DOS was successfully poisoned! cb: %s \n%s\n", cb, request.URL)
			m.Lock()
			_ = checkPoisoningIndicators(repResult, request, msg, "", "", statusCode1, statusCode2, false, respHeader, false)
			m.Unlock()

			<-sem
		}(repetition)
	}

	wg.Wait()
}

func headerDOSTemplate(repResult *reportResult, values []string, header string, msgextra string, httpConform bool) {
	msg := fmt.Sprintf("Testing now %sDOS with header %s and values %s\n", msgextra, header, values)
	PrintVerbose(msg, NoColor, 2)

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(values))
	var m sync.Mutex

	for _, value := range values {

		go func(value string, httpConform bool) {
			defer wg.Done()
			sem <- 1

			msg := fmt.Sprintf("Testing now %s Header DOS with %s\n", header, value)
			PrintVerbose(msg, NoColor, 2)
			rUrl := Config.Website.Url.String()
			cb := randInt()
			success := fmt.Sprintf("%sDOS with header %s was successfully poisoned! cb: %s poison: %s\n", msgextra, header, cb, value)
			identifier := fmt.Sprintf("%s%s with %s", msgextra, header, value)

			rp := requestParams{
				repResult:        repResult,
				headers:          []string{header},
				values:           []string{value},
				identifier:       identifier,
				poison:           "",
				url:              rUrl,
				cb:               cb,
				success:          success,
				bodyString:       "",
				forcePost:        false,
				duplicateHeaders: false,
				m:                &m,
				newCookie:        http.Cookie{},
			}
			responseSplitting, _ := issueRequest(rp)

			// check for response splitting, if poison was reflected in a header
			if responseSplitting {
				msg := fmt.Sprintf("Testing now %s Header DOS with %s\n for Response Splitting, because it was reflected in the response' header", header, value)
				PrintVerbose(msg, Cyan, 1)

				rp.values[0] += getRespSplit()
				rp.url = rUrl
				rp.cb = randInt()
				rp.success = fmt.Sprintf("%sDOS with header %s was successfully poisoned with Response Splitting! cb: %s poison: %s\n", msgextra, header, rp.cb, rp.values[0])
				rp.identifier += getRespSplit() + " with response splitting"

				issueRequest(rp)
			}

			<-sem
		}(value, httpConform)
	}
	wg.Wait()
}

func ScanCSS() reportResult {
	var repResult reportResult
	repResult.Technique = "CSS poisoning"

	bodyReader := strings.NewReader(Config.Website.Body)
	tokenizer := html.NewTokenizer(bodyReader)

	var urls []string

	eof := false
	for !eof {
		tokentype := tokenizer.Next()

		switch tokentype {
		case html.StartTagToken, html.SelfClosingTagToken:

			token := tokenizer.Token()

			if token.Data == "link" {
				for _, a := range token.Attr {
					if a.Key == "href" {
						if !strings.HasSuffix(a.Val, ".css") {
							break
						}
						tempURL := addDomain(a.Val, Config.Website.Domain)
						if tempURL != "" {
							urls = append(urls, tempURL)
						}
						break
					}
				}
			}
		// When EOF is reached a html.ErrorToken appears
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				eof = true
				break
			}
			msg := fmt.Sprintf("error tokenizing HTML: %+v", tokenizer.Err())
			Print(msg, Yellow)
		}
	}

	if len(urls) == 0 {
		msg := "No CSS files were found.\n"
		PrintVerbose(msg, Yellow, 1)

		return repResult
	}
	msg := fmt.Sprintf("Testing the following CSS files for poisoning\n%s\n", urls)
	PrintVerbose(msg, NoColor, 1)

	sem := make(chan int, Config.Threads)
	var wg sync.WaitGroup
	wg.Add(len(urls))
	var m sync.Mutex

	for _, url := range urls {

		go func(url string) {
			defer wg.Done()
			sem <- 1

			//msg := fmt.Sprintf("Testing now %s Header DOS with %s\n", header, value)
			//Print(msg, NoColor)

			urlWithCb, cb := addCachebusterParameter(url, "")

			identifier := url
			rp := requestParams{
				identifier: identifier,
				url:        urlWithCb,
				cb:         randInt(),
			}
			body, _, request, _, err := firstRequest(rp)
			if err != nil {
				if err.Error() != "stop" {
					m.Lock()
					repResult.HasError = true
					repResult.ErrorMessages = append(repResult.ErrorMessages, err.Error())
					m.Unlock()
				}
				<-sem
				return
			}

			if strings.Contains(string(body), cb) {
				msg = fmt.Sprintf("The following CSS file reflects the url with the cb %s\n%s\n", cb, url)
				Print(msg, Green)
			}

			body, _, _, err = secondRequest(url, identifier, rp.cb)
			if err != nil {
				if err.Error() != "stop" {
					m.Lock()
					repResult.HasError = true
					repResult.ErrorMessages = append(repResult.ErrorMessages, err.Error())
					m.Unlock()
				}
				<-sem
				return
			}

			if strings.Contains(string(body), cb) {
				PrintNewLine()
				msg = fmt.Sprintf("A CSS file was successfully poisoned! cb: %s\nURL: %s\n", cb, request.URL)
				Print(msg, Green)
				msg = "Reason: CSS reflects URL\n"
				Print(msg, Green)

				m.Lock()
				repResult.Vulnerable = true
				repResult.Requests = append(repResult.Requests, request)
				m.Unlock()
			}

			<-sem
		}(url)

	}
	wg.Wait()

	return repResult
}
