package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var (
	hitmissindicator       map[string]int
	cachebuster            map[string]int
	total_hitmissindicator map[string]int
	total_cachebuster      map[string]int
	once_hitmissindicator  map[string]int
	once_cachebuster       map[string]int
	Statistics             map[string]int

	timeFalsePos []int64
	timeFalseNeg []int64

	countFalsePos []int
	countFalseNeg []int

	boolFalsePos bool
	boolFalseNeg bool

	cb_method    bool
	cb_cookie    bool
	cb_parameter bool
	cb_header    bool
)

func init() {
	hitmissindicator = map[string]int{}
	cachebuster = map[string]int{}
	once_hitmissindicator = map[string]int{}
	once_cachebuster = map[string]int{}
	total_hitmissindicator = map[string]int{}
	total_cachebuster = map[string]int{}

	countFalsePos = []int{0, 0}
	countFalseNeg = []int{0, 0}
}

func addFalsePos() {
	if !boolFalsePos {
		boolFalsePos = true
		countFalsePos[0]++
	}
	countFalsePos[1]++
}

func addFalseNeg() {
	if !boolFalseNeg {
		boolFalseNeg = true
		countFalseNeg[0]++
	}
	countFalseNeg[1]++
}

func cbFoundDifference(times []int64, identifier string) {
	if len(times)%2 == 0 {
		for i := 0; i < len(times); i += 2 {
			dif := times[i] - times[i+1]
			if dif < int64(Config.HMDiff) {
				msg := fmt.Sprintf("The time difference (%d) was smaller than the threshold (%d)\n", dif, Config.HMDiff)
				PrintVerbose(msg, White, 2)
				timeFalseNeg = append(timeFalseNeg, dif)
				addFalseNeg()
				return
			}
		}
	} else {
		msg := fmt.Sprintf("%s: len(times) mod 2 != 0\n", identifier)
		Print(msg, Yellow)
	}
}

func cbNotFoundDifference(times []int64, identifier string) {
	if len(times)%2 == 0 {
		for i := 0; i < len(times); i += 2 {
			dif := times[i] - times[i+1]
			if dif >= int64(Config.HMDiff) {
				msg := fmt.Sprintf("The time difference (%d) was equal or higher than the threshold (%d)", dif, Config.HMDiff)
				Print(msg, Yellow)
				timeFalsePos = append(timeFalsePos, dif)
				addFalsePos()
				return
			}
		}
	} else {
		msg := fmt.Sprintf("%s: len(times) mod 2 != 0", identifier)
		Print(msg, Yellow)
	}
}

func addHitMissIndicatorMap(name string) {
	hitmissindicator[name]++
	if hitmissindicator[name] == 1 {
		once_hitmissindicator[name]++
	}
	total_hitmissindicator[name]++
}

func addCachebusterMap(name string) {
	cachebuster[name]++
	if cachebuster[name] == 1 {
		once_cachebuster[name]++
	}
	total_cachebuster[name]++
}

/* Check if the parameter "cb" (or any other defined by flag -cb), the headers "accept-encoding, accept, cookie, origin" or any cookie can be used as cachebuster */
func CheckCache(stat string) (CacheStruct, []error) {
	if strings.Contains(stat, "sub") {
		hitmissindicator = map[string]int{}
		cachebuster = map[string]int{}
	}

	cb_method = false
	cb_cookie = false
	cb_parameter = false
	cb_header = false

	boolFalseNeg = false
	boolFalsePos = false

	var cache CacheStruct
	var errSlice []error

	// analyze the website headers
	for key, val := range Config.Website.Headers {
		switch strings.ToLower(key) {
		case "cache-control", "pragma":
			msg := fmt.Sprintf("%s header was found: %s \n", key, val)
			PrintVerbose(msg, NoColor, 1)
		case "x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish-cache", "akamai-cache-status", "server-timing", "x-iinfo", "x-nc", "x-hs-cf-cache-status", "x-proxy-cache", "x-cache-hits":
			cache.Indicator = key
			msg := fmt.Sprintf("%s header was found: %s \n", key, val)
			PrintVerbose(msg, NoColor, 1)
			addHitMissIndicatorMap(strings.ToLower(key))
		case "age":
			// only set it it wasn't set to x-cache or sth. similar beforehand
			if cache.Indicator == "" {
				cache.Indicator = key
				msg := fmt.Sprintf("%s header was found: %s\n", key, val)
				PrintVerbose(msg, NoColor, 1)
				if cache.Indicator == "" {
					cache.Indicator = "age"
				}
				addHitMissIndicatorMap(strings.ToLower("age"))
			}
		}
	}

	addHitMissIndicatorMap("total")
	addCachebusterMap("total")

	alwaysMiss := false
	var err error
	if cache.Indicator == "" {
		msg := "No x-cache (or other cache hit/miss header) header was found\nThe time will be measured as cache hit/miss indicator\n"
		Print(msg, Yellow)
	} else {
		alwaysMiss, err = checkIfAlwaysMiss(cache)
		if err != nil {
			errSlice = append(errSlice, err)
		}
	}

	// test for cachebuster, if the cache doesnt always return a miss
	if !alwaysMiss {
		// Check first if a parameter can be used as cachebuster
		if !cache.CBwasFound {
			err = cachebusterParameter(&cache)
			if err != nil {
				errSlice = append(errSlice, err)
			}
		}

		// Check second if a header can be used as cachebuster
		if !cache.CBwasFound {
			errs := cachebusterHeader(&cache)
			if err != nil {
				errSlice = append(errSlice, errs...)
			}
		}

		// Check third if a cookie can be used as cachebuster
		if !cache.CBwasFound {
			errs := cachebusterCookie(&cache)
			if err != nil {
				errSlice = append(errSlice, errs...)
			}
		}

		// Check fourth if a HTTP Method can be used as cachebuster
		if !cache.CBwasFound {
			errs := cachebusterHTTPMethod(&cache)
			if err != nil {
				errSlice = append(errSlice, errs...)
			}
		}

		totalCachebusters := "comb_"
		if cb_method {
			addCachebusterMap("total_httpmethods")
			totalCachebusters += "httpmethod"
		}
		if cb_cookie {
			addCachebusterMap("total_cookies")
			totalCachebusters += "cookie"
		}
		if cb_header {
			addCachebusterMap("total_headers")
			totalCachebusters += "header"
		}
		if cb_parameter {
			addCachebusterMap("total_parameters")
			totalCachebusters += "parameter"
		}
		if cache.CBwasFound {
			addCachebusterMap(totalCachebusters)
		}
	}

	if cache.Indicator == "" && !cache.TimeIndicator {
		msg := "No cache indicator could be found"
		Print(msg+"\n", Yellow)
		errSlice = append(errSlice, errors.New(strings.ToLower(msg)))

		addHitMissIndicatorMap("none")
		addCachebusterMap("none")
	} else {
		addHitMissIndicatorMap("found")

		if !cache.CBwasFound {
			msg := "No cachebuster could be found"
			Print(msg+"\n", Yellow)
			errSlice = append(errSlice, errors.New(strings.ToLower(msg)))

			addCachebusterMap("none")
		} else {
			addCachebusterMap("found")
		}
	}

	if (!cache.CBwasFound || (cache.Indicator == "" && !cache.TimeIndicator)) && !Config.Force {
		msg := "Use -f/-force to force the test\n"
		Print(msg, Yellow)
	}

	msg := fmt.Sprintf("Statistics:\nGeneral: %+v\nIndicator: %+v\nCachebuster: %+v\nOnce_Indicator: %+v\nOnce_Cachebuster: %+v\nTotal_Indicator: %+v\nTotal_Cachebuster: %+v\nTimeFalseNeg: %+v: %+v\nTimeFalsePos: %+v: %+v\n",
		Statistics, hitmissindicator, cachebuster, once_hitmissindicator, once_cachebuster, total_hitmissindicator, total_cachebuster, countFalseNeg, timeFalseNeg, countFalsePos, timeFalsePos)
	PrintVerbose(msg, Cyan, 2)

	return cache, errSlice
}

func checkIfAlwaysMiss(cache CacheStruct) (bool, error) {
	errorString := "checkIfAlwaysMiss"

	var req *http.Request
	var err error

	weburl := Config.Website.Url.String()
	if Config.DoPost {
		req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
	} else {
		req, err = http.NewRequest("GET", weburl, nil)
	}
	if err != nil {
		msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
		Print(msg+"\n", Red)
		return false, errors.New(msg)
	}

	setRequest(req, Config.DoPost, "", http.Cookie{})

	waitLimiter(errorString)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
		Print(msg+"\n", Red)
		return false, errors.New(msg)
	}
	defer resp.Body.Close()

	firstUnix := time.Now().Unix()

	if resp.StatusCode != Config.Website.StatusCode {
		msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
		Print(msg, Yellow)
	}

	setRequest(req, Config.DoPost, "", http.Cookie{})

	waitLimiter(errorString)

	secondUnix := time.Now().Unix()
	timeDiff := secondUnix - firstUnix
	// make sure that there is at least 2 sec difference.
	// So that first req has Age=0 and second req has Age>=2
	if timeDiff <= 1 && strings.EqualFold("age", cache.Indicator) {
		time.Sleep(2 * time.Second)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
		Print(msg+"\n", Red)
		return false, errors.New(msg)
	}
	defer resp.Body.Close()

	if resp.StatusCode != Config.Website.StatusCode {
		msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
		Print(msg, Yellow)
	}

	indicValue := strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
	if !checkCacheHit(indicValue) {
		addCachebusterMap("always-miss")

		msg := "Cache returns always miss"
		Print(msg+"\n", Yellow)
		return true, errors.New(msg)
	}

	return false, nil
}

func cachebusterCookie(cache *CacheStruct) []error {
	var errSlice []error
	for i, c := range Config.Website.Cookies {
		errorString := "cachebusterCookie " + c.Name
		identifier := "Cookie " + c.Name + " as Cachebuster"

		var req *http.Request
		var err error
		var times []int64

		if cache.Indicator == "" {
			// No Cache Indicator was found. So time will be used as Indicator
			var newCookie http.Cookie
			var cb string
			for ii := 0; ii < 5*2; ii++ {
				weburl := Config.Website.Url.String()
				if Config.DoPost {
					req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
				} else {
					req, err = http.NewRequest("GET", weburl, nil)
				}
				if err != nil {
					msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}

				if ii%2 == 0 {
					cb = randInt()
					newCookie = *c
					newCookie.Value = cb
				}
				setRequest(req, Config.DoPost, "", newCookie)

				waitLimiter(errorString)
				start := time.Now()
				resp, err := http.DefaultClient.Do(req)
				elapsed := time.Since(start).Milliseconds()
				times = append(times, elapsed)
				if err != nil {
					msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != Config.Website.StatusCode {
					msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
					Print(msg, Yellow)
				}
			}
			msg := fmt.Sprintf("measured times: %d\n", times)
			PrintVerbose(msg, NoColor, 2)

			skip := false
			for ii := range times {
				// Cache miss has to take 30ms (misshitdif) longer than cache hit
				if ii%2 == 1 && times[ii-1]-times[ii] < int64(Config.HMDiff) {
					msg := fmt.Sprintf("%s was not successful (Cookie)\n", identifier)
					PrintVerbose(msg, NoColor, 2)
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			cache.TimeIndicator = true
			cache.CBwasFound = true
			cache.CBisCookie = true
			cache.CBisHTTPMethod = false
			cache.CBisHeader = false
			cache.CBisParameter = false
			cache.CBName = Config.Website.Cookies[i].Name
			cb_cookie = true
			addHitMissIndicatorMap("time")
			addCachebusterMap("cookie_" + Config.Website.Cookies[i].Name)

			msg = fmt.Sprintf("%s was successful (Cookie, time was used as indicator)\n", identifier)
			Print(msg, Cyan)
		} else {
			// A hit miss Indicator was found. Sending 2 requests, each with a new cachebuster, expecting 2 misses
			weburl := Config.Website.Url.String()
			if Config.DoPost {
				req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
			} else {
				req, err = http.NewRequest("GET", weburl, nil)
			}
			if err != nil {
				msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				errSlice = append(errSlice, errors.New(msg))
				continue
			}

			cb := randInt()
			newCookie := *c
			newCookie.Value = cb
			setRequest(req, Config.DoPost, "", newCookie)

			waitLimiter(errorString)

			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start).Milliseconds()
			times = append(times, elapsed)

			if err != nil {
				msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				errSlice = append(errSlice, errors.New(msg))
				continue
			}

			defer resp.Body.Close()

			firstUnix := time.Now().Unix()

			if resp.StatusCode != Config.Website.StatusCode {
				msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
				Print(msg, Yellow)
			}

			indicValue := strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
			if checkCacheHit(indicValue) {
				// If there is a hit, the cachebuster didn't work
				msg := fmt.Sprintf("%s was not successful (Cookie)\n", identifier)
				PrintVerbose(msg, NoColor, 2)
				continue
			} else {
				if Config.DoPost {
					req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
				} else {
					req, err = http.NewRequest("GET", weburl, nil)
				}
				if err != nil {
					msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}

				cb = randInt()
				c.Value = cb
				setRequest(req, Config.DoPost, "", *c)

				waitLimiter(errorString)

				secondUnix := time.Now().Unix()
				timeDiff := secondUnix - firstUnix
				// make sure that there is at least 2 sec difference.
				// So that first req has Age=0 and second req has Age>=2
				if timeDiff <= 1 && strings.EqualFold("age", cache.Indicator) {
					time.Sleep(2 * time.Second)
				}

				start := time.Now()
				resp, err := http.DefaultClient.Do(req)
				elapsed := time.Since(start).Milliseconds()
				times = append(times, elapsed)
				if err != nil {
					msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != Config.Website.StatusCode {
					msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
					Print(msg, Yellow)
				}

				indicValue = strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
				if checkCacheHit(indicValue) {
					// If there is a hit, the cachebuster didn't work
					msg := fmt.Sprintf("%s was not successful (Cookie)\n", identifier)
					PrintVerbose(msg, NoColor, 2)
					cbNotFoundDifference(times, identifier)
				} else {
					cache.CBwasFound = true
					cache.CBisCookie = true
					cache.CBisHTTPMethod = false
					cache.CBisHeader = false
					cache.CBisParameter = false
					cache.CBName = Config.Website.Cookies[i].Name
					cb_cookie = true
					addCachebusterMap("cookie_" + Config.Website.Cookies[i].Name)

					msg := fmt.Sprintf("%s was successful (Cookie)\n", identifier)
					Print(msg, Cyan)

					cbFoundDifference(times, identifier)
					continue
				}
			}
		}
	}

	return errSlice
}

func cachebusterHeader(cache *CacheStruct) []error {
	headers := []string{"Accept-Encoding", "Accept", "Cookie", "Origin"}
	values := []string{"gzip, deflate, ", "*/*, text/", "wcvs_cookie=", ""}

	var errSlice []error

	for i, header := range headers {
		errorString := "cachebusterHeader " + header
		identifier := "Header " + header + " as Cachebuster"

		var req *http.Request
		var err error
		var times []int64

		if cache.Indicator == "" {
			// No Cache Indicator was found. So time will be used as Indicator
			var cb string
			for ii := 0; ii < 5*2; ii++ {
				weburl := Config.Website.Url.String()
				if Config.DoPost {
					req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
				} else {
					req, err = http.NewRequest("GET", weburl, nil)
				}
				if err != nil {
					msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}

				setRequest(req, Config.DoPost, "", http.Cookie{})
				if ii%2 == 0 {
					cb = values[i] + randInt()
					if h := req.Header.Get(header); h != "" {
						msg := fmt.Sprintf("Overwriting %s:%s with %s:%s\n", header, h, header, cb)
						Print(msg, NoColor)
					}
					req.Header.Set(header, cb)
				}

				waitLimiter(errorString)
				start := time.Now()
				resp, err := http.DefaultClient.Do(req)
				elapsed := time.Since(start).Milliseconds()
				times = append(times, elapsed)
				if err != nil {
					msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != Config.Website.StatusCode {
					msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
					Print(msg, Yellow)
				}
			}
			msg := fmt.Sprintf("measured times: %d\n", times)
			PrintVerbose(msg, NoColor, 2)

			skip := false
			for ii := range times {
				// Cache miss has to take 30ms (misshitdif) longer than cache hit
				if ii%2 == 1 && times[ii-1]-times[ii] < int64(Config.HMDiff) {
					msg := fmt.Sprintf("%s was not successful (Header)\n", identifier)
					PrintVerbose(msg, NoColor, 2)
					skip = true
					break
				}
			}
			if skip {
				continue
			}

			cache.TimeIndicator = true
			cache.CBwasFound = true
			cache.CBisHeader = true
			cache.CBisCookie = false
			cache.CBisHTTPMethod = false
			cache.CBisParameter = false
			cache.CBName = header
			cb_header = true
			addHitMissIndicatorMap("time")
			addCachebusterMap("header_" + header)

			msg = fmt.Sprintf("%s was successful (Header, time was used as indicator)\n", identifier)
			Print(msg, Cyan)

			continue
		} else {
			// A hit miss Indicator was found. Sending 2 requests, each with a new cachebuster, expecting 2 misses
			weburl := Config.Website.Url.String()
			if Config.DoPost {
				req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
			} else {
				req, err = http.NewRequest("GET", weburl, nil)
			}
			if err != nil {
				msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				errSlice = append(errSlice, errors.New(msg))
				continue
			}

			setRequest(req, Config.DoPost, "", http.Cookie{})
			cb := values[i] + randInt()
			if h := req.Header.Get(header); h != "" {
				msg := fmt.Sprintf("Overwriting %s:%s with %s:%s\n", header, h, header, cb)
				Print(msg, NoColor)
			}
			req.Header.Set(header, cb)

			waitLimiter(errorString)
			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start).Milliseconds()
			times = append(times, elapsed)
			if err != nil {
				msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				errSlice = append(errSlice, errors.New(msg))
				continue
			}
			defer resp.Body.Close()

			firstUnix := time.Now().Unix()

			if resp.StatusCode != Config.Website.StatusCode {
				msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
				Print(msg, Yellow)
			}

			indicValue := strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
			if checkCacheHit(indicValue) {
				// If there is a hit, the cachebuster didn't work
				msg := fmt.Sprintf("%s was not successful (Header)\n", identifier)
				PrintVerbose(msg, NoColor, 2)
				continue
			} else {

				if Config.DoPost {
					req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
				} else {
					req, err = http.NewRequest("GET", weburl, nil)
				}
				if err != nil {
					msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}

				setRequest(req, Config.DoPost, "", http.Cookie{})
				cb = values[i] + randInt()
				if h := req.Header.Get(header); h != "" {
					msg := fmt.Sprintf("Overwriting %s:%s with %s:%s\n", header, h, header, cb)
					Print(msg, NoColor)
				}
				req.Header.Set(header, cb)

				waitLimiter(errorString)

				secondUnix := time.Now().Unix()
				timeDiff := secondUnix - firstUnix
				// make sure that there is at least 2 sec difference.
				// So that first req has Age=0 and second req has Age>=2
				if timeDiff <= 1 && strings.EqualFold("age", cache.Indicator) {
					time.Sleep(2 * time.Second)
				}

				start := time.Now()
				resp, err := http.DefaultClient.Do(req)
				elapsed := time.Since(start).Milliseconds()
				times = append(times, elapsed)
				if err != nil {
					msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != Config.Website.StatusCode {
					msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
					Print(msg, Yellow)
				}

				indicValue = strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
				if checkCacheHit(indicValue) {
					// If there is a hit, the cachebuster didn't work
					msg := fmt.Sprintf("%s was not successful (Header)\n", identifier)
					PrintVerbose(msg, NoColor, 2)

					cbNotFoundDifference(times, identifier)
				} else {
					cache.CBwasFound = true
					cache.CBisHeader = true
					cache.CBisCookie = false
					cache.CBisHTTPMethod = false
					cache.CBisParameter = false
					cache.CBName = header
					cb_header = true
					addCachebusterMap("header_" + header)

					msg := fmt.Sprintf("%s was successful (Header)\n", identifier)
					Print(msg, Cyan)

					cbFoundDifference(times, identifier)
					continue
				}
			}
		}
	}
	return errSlice
}

func cachebusterParameter(cache *CacheStruct) error {
	errorString := "cachebusterParameter"
	identifier := "Parameter " + Config.CacheBuster + " as Cachebuster"

	var req *http.Request
	var err error
	var times []int64

	if cache.Indicator == "" {
		// No Cache Indicator was found. So time will be used as Indicator
		var urlCb string
		for i := 0; i < 5*2; i++ {
			if i%2 == 0 {
				urlCb, _ = addCachebusterParameter(Config.Website.Url.String(), "")
			}
			if Config.DoPost {
				req, err = http.NewRequest("POST", urlCb, bytes.NewBufferString(Config.Body))
			} else {
				req, err = http.NewRequest("GET", urlCb, nil)
			}
			if err != nil {
				msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				return errors.New(msg)
			}

			setRequest(req, Config.DoPost, "", http.Cookie{})

			waitLimiter(errorString)
			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start).Milliseconds()
			times = append(times, elapsed)
			if err != nil {
				msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				return errors.New(msg)
			}
			defer resp.Body.Close()

			if resp.StatusCode != Config.Website.StatusCode {
				msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
				Print(msg, Yellow)
			}
		}
		msg := fmt.Sprintf("measured times: %d\n", times)
		PrintVerbose(msg, NoColor, 2)

		for i := range times {
			// Cache miss has to take 30ms (misshitdif) longer than cache hit
			if i%2 == 1 && times[i-1]-times[i] < int64(Config.HMDiff) {
				msg := fmt.Sprintf("%s was not successful (Parameter)\n", identifier)
				PrintVerbose(msg, NoColor, 2)
				return nil
			}
		}
		cache.TimeIndicator = true
		cache.CBwasFound = true
		cache.CBisParameter = true
		cache.CBisHeader = false
		cache.CBisCookie = false
		cache.CBisHTTPMethod = false
		cache.CBName = Config.CacheBuster
		cb_parameter = true
		addHitMissIndicatorMap("time")
		addCachebusterMap(Config.CacheBuster)

		msg = fmt.Sprintf("%s was successful (Parameter, time was used as indicator)\n", identifier)
		Print(msg, Cyan)
	} else {
		// A hit miss Indicator was found. Sending 2 requests, each with a new cachebuster, expecting 2 misses
		urlCb, _ := addCachebusterParameter(Config.Website.Url.String(), "")

		if Config.DoPost {
			req, err = http.NewRequest("POST", urlCb, bytes.NewBufferString(Config.Body))
		} else {
			req, err = http.NewRequest("GET", urlCb, nil)
		}
		if err != nil {
			msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
			Print(msg+"\n", Red)
			return errors.New(msg)
		}

		setRequest(req, Config.DoPost, "", http.Cookie{})
		waitLimiter(errorString)
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		elapsed := time.Since(start).Milliseconds()
		times = append(times, elapsed)
		if err != nil {
			msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
			Print(msg+"\n", Red)
			return errors.New(msg)
		}
		defer resp.Body.Close()

		firstUnix := time.Now().Unix()

		if resp.StatusCode != Config.Website.StatusCode {
			msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
			Print(msg, Yellow)
		}

		indicValue := strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
		if checkCacheHit(indicValue) {
			// If there is a hit, the cachebuster didn't work
			msg := fmt.Sprintf("%s was not successful (Parameter)\n", identifier)
			PrintVerbose(msg, NoColor, 2)
		} else {
			urlCb, _ := addCachebusterParameter(Config.Website.Url.String(), "")

			if Config.DoPost {
				req, err = http.NewRequest("POST", urlCb, bytes.NewBufferString(Config.Body))
			} else {
				req, err = http.NewRequest("GET", urlCb, nil)
			}
			if err != nil {
				msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				return errors.New(msg)
			}

			setRequest(req, Config.DoPost, "", http.Cookie{})
			waitLimiter(errorString)

			secondUnix := time.Now().Unix()
			timeDiff := secondUnix - firstUnix
			// make sure that there is at least 2 sec difference.
			// So that first req has Age=0 and second req has Age>=2
			if timeDiff <= 1 && strings.EqualFold("age", cache.Indicator) {
				time.Sleep(2 * time.Second)
			}

			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start).Milliseconds()
			times = append(times, elapsed)
			if err != nil {
				msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				return errors.New(msg)
			}
			defer resp.Body.Close()

			if resp.StatusCode != Config.Website.StatusCode {
				msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
				Print(msg, Yellow)
			}

			indicValue = strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
			if checkCacheHit(indicValue) {
				// If there is a hit, the cachebuster didn't work
				msg := fmt.Sprintf("%s was not successful (Parameter)\n", identifier)
				PrintVerbose(msg, NoColor, 2)

				cbNotFoundDifference(times, identifier)
			} else {
				cache.CBwasFound = true
				cache.CBisParameter = true
				cache.CBisHeader = false
				cache.CBisCookie = false
				cache.CBisHTTPMethod = false
				cache.CBName = Config.CacheBuster
				cb_parameter = true
				addCachebusterMap(Config.CacheBuster)

				msg := fmt.Sprintf("%s was successful (Parameter)\n", identifier)
				Print(msg, Cyan)

				cbFoundDifference(times, identifier)
			}
		}
	}

	return nil
}

func cachebusterHTTPMethod(cache *CacheStruct) []error {
	http_methods := []string{"PURGE", "FASTLYPURGE"}

	var errSlice []error

	for _, method := range http_methods {
		errorString := "cachebusterHTTPMethod " + method
		identifier := "HTTP Method " + method + " as Cachebuster"

		var req *http.Request
		var err error
		var times []int64

		if cache.Indicator == "" {
			// No Cache Indicator was found. So time will be used as Indicator
			skip := false
			for ii := 0; ii < 5*2; ii++ {
				weburl := Config.Website.Url.String()
				if ii%2 == 0 {
					req, err = http.NewRequest(method, weburl, nil)
				} else {
					if Config.DoPost {
						req, err = http.NewRequest("POST", weburl, bytes.NewBufferString(Config.Body))
					} else {
						req, err = http.NewRequest("GET", weburl, nil)
					}
				}
				if err != nil {
					msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}

				setRequest(req, Config.DoPost, "", http.Cookie{})

				waitLimiter(errorString)
				start := time.Now()
				resp, err := http.DefaultClient.Do(req)
				elapsed := time.Since(start).Milliseconds()
				times = append(times, elapsed)
				if err != nil {
					msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != Config.Website.StatusCode {
					msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
					Print(msg, Yellow)
				}
				if resp.StatusCode >= 400 {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			msg := fmt.Sprintf("measured times: %d\n", times)
			PrintVerbose(msg, NoColor, 2)

			skip = false
			for ii := range times {
				// Cache miss has to take 30ms (misshitdif) longer than cache hit
				if ii%2 == 1 && times[ii-1]-times[ii] < int64(Config.HMDiff) {
					msg := fmt.Sprintf("%s was not successful (HTTP Method)\n", identifier)
					PrintVerbose(msg, NoColor, 2)
					skip = true
					break
				}
			}
			if skip {
				continue
			}

			cache.TimeIndicator = true
			cache.CBwasFound = true
			cache.CBisHTTPMethod = true
			cache.CBisParameter = false
			cache.CBisHeader = false
			cache.CBisCookie = false
			cache.CBName = method
			cb_method = true
			addHitMissIndicatorMap("time")
			addCachebusterMap("method_" + method)

			msg = fmt.Sprintf("%s was successful (HTTP Method, time was used as indicator)\n", identifier)
			Print(msg, Cyan)

			continue
		} else {
			// A hit miss Indicator was found. Sending 2 requests, each with a new cachebuster, expecting 2 misses
			weburl := Config.Website.Url.String()
			req, err = http.NewRequest(method, weburl, bytes.NewBufferString(Config.Body))
			if err != nil {
				msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				errSlice = append(errSlice, errors.New(msg))
				continue
			}
			setRequest(req, Config.DoPost, "", http.Cookie{})

			waitLimiter(errorString)
			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start).Milliseconds()
			times = append(times, elapsed)
			if err != nil {
				msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				errSlice = append(errSlice, errors.New(msg))
				continue
			}
			defer resp.Body.Close()

			firstUnix := time.Now().Unix()

			if resp.StatusCode != Config.Website.StatusCode {
				msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
				Print(msg, Yellow)
			}
			if resp.StatusCode >= 400 {
				continue
			}

			indicValue := strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
			if checkCacheHit(indicValue) {
				// If there is a hit, the cachebuster didn't work
				msg := fmt.Sprintf("%s was not successful (HTTP Method)\n", identifier)
				PrintVerbose(msg, NoColor, 2)
			} else {
				req, err = http.NewRequest(method, weburl, bytes.NewBufferString(Config.Body))
				if err != nil {
					msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				setRequest(req, Config.DoPost, "", http.Cookie{})
				waitLimiter(errorString)

				secondUnix := time.Now().Unix()
				timeDiff := secondUnix - firstUnix
				// make sure that there is at least 2 sec difference.
				// So that first req has Age=0 and second req has Age>=2
				if timeDiff <= 1 && strings.EqualFold("age", cache.Indicator) {
					time.Sleep(2 * time.Second)
				}

				start := time.Now()
				resp, err := http.DefaultClient.Do(req)
				elapsed := time.Since(start).Milliseconds()
				times = append(times, elapsed)
				if err != nil {
					msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error())
					Print(msg+"\n", Red)
					errSlice = append(errSlice, errors.New(msg))
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != Config.Website.StatusCode {
					msg := fmt.Sprintf("%s: Unexpected Status Code: %d\n", errorString, resp.StatusCode)
					Print(msg, Yellow)
				}
				if resp.StatusCode >= 400 {
					continue
				}

				indicValue = strings.TrimSpace(strings.ToLower(resp.Header.Get(cache.Indicator)))
				if checkCacheHit(indicValue) {
					// If there is a hit, the cachebuster didn't work
					msg := fmt.Sprintf("%s was not successful (HTTP Method)\n", identifier)
					PrintVerbose(msg, NoColor, 2)

					cbNotFoundDifference(times, identifier)
				} else {
					cache.CBwasFound = true
					cache.CBisHTTPMethod = true
					cache.CBisParameter = false
					cache.CBisHeader = false
					cache.CBisCookie = false
					cache.CBName = method
					cb_method = true
					addCachebusterMap("method_" + method)

					msg := fmt.Sprintf("%s was successful (HTTP Method)\n", identifier)
					Print(msg, Cyan)

					cbFoundDifference(times, identifier)

					continue
				}
			}
		}
	}
	return errSlice
}

/* Simple get request to get the body of a normal response and the cookies */
func GetWebsite(requrl string, setStatusCode bool, cacheBuster bool) (WebsiteStruct, error) {
	errorString := "GetWebsite"

	var web WebsiteStruct
	cache := Config.Website.Cache
	queryParameterMap := make(map[string]string)

	// get domain
	domainParts := strings.SplitN(requrl, "/", 4)
	domain := domainParts[0] + "//" + domainParts[2]

	// splitting url like {https://www.m10x.de/}?{name=max&role=admin}
	urlSlice := strings.SplitN(requrl, "?", 2)

	// splitting queries like {name=max}&{role=admin}
	var parameterSlice []string
	if strings.Contains(requrl, "?") {
		parameterSlice = strings.Split(urlSlice[1], Config.QuerySeperator)
	}

	if len(parameterSlice) > 0 {
		queryParameterMap = setQueryParameterMap(queryParameterMap, parameterSlice)
	}

	if len(Config.Parameters) > 0 {
		queryParameterMap = setQueryParameterMap(queryParameterMap, Config.Parameters)
	}

	requrl = urlSlice[0]
	urlNoQueries := urlSlice[0]

	// adding query parameter
	for key, val := range queryParameterMap {
		if !strings.Contains(requrl, "?") {
			requrl += "?"
		} else {
			requrl += Config.QuerySeperator
		}
		requrl += key + "=" + val
	}

	cb := ""
	if cacheBuster {
		cb = randInt()
	}

	var req *http.Request
	var err error
	if Config.Website.Cache.CBisHTTPMethod {
		req, err = http.NewRequest(Config.Website.Cache.CBName, requrl, bytes.NewBufferString(Config.Body))
	} else if Config.DoPost {
		req, err = http.NewRequest("POST", requrl, bytes.NewBufferString(Config.Body))
	} else {
		req, err = http.NewRequest("GET", requrl, nil)
	}
	if err != nil {
		msg := fmt.Sprintf("%s: http.NewRequest: %s", errorString, err.Error())
		Print(msg+"\n", Red)
		return web, errors.New(msg)
	}

	setRequest(req, Config.DoPost, cb, http.Cookie{})
	waitLimiter(errorString)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("%s: http.DefaultClient.Do: %s", errorString, err.Error()) // Error: context deadline exceeded -> panic; runtime error

		Print(msg+"\n", Red)
		return web, errors.New(msg)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("%s: ioutil.ReadAll: %s", errorString, err.Error())
		Print(msg+"\n", Red)
		return web, errors.New(msg)
	}

	weburl, err := url.Parse(requrl)
	if err != nil {
		msg := fmt.Sprintf("%s: url.Parse: %s", errorString, err.Error())
		Print(msg+"\n", Red)
		return web, errors.New(msg)
	}

	tempStatusCode := Config.Website.StatusCode
	// Only overwrite statuscode if 1. it wasn't set via flag 2. its the first and only request or the second of two requests
	if setStatusCode && tempStatusCode != resp.StatusCode {
		tempStatusCode = resp.StatusCode

		cache = Config.Website.Cache

		msg := fmt.Sprintf("The default status code was set to %d\n", tempStatusCode)
		Print(msg, Cyan)
	}

	// if retrieveCookies is false, only the specified cookies will be used
	// otherwise the by the server given cookies AND the specified cookies will be used
	cookiesWebsite := Config.Website.Cookies
	if !Config.DeclineCookies {
		cookiesWebsite = append(cookiesWebsite, resp.Cookies()...)
	}

	/*
		weburl.Host:		www.example.com
		weburl.Path:		/
		weburl.Hostname():www.example.com
		weburl.String():	https://www.example.com/?test=12
		domain:			https://www.example.com
		urlNoQueries:		https://www.example.com/
	*/

	web = WebsiteStruct{
		Headers:      resp.Header,
		Body:         string(body),
		Cookies:      cookiesWebsite,
		StatusCode:   tempStatusCode,
		Url:          weburl,
		UrlWOQueries: urlNoQueries,
		Queries:      queryParameterMap,
		Cache:        cache,
		Domain:       domain,
		//make map doesnt work here. is now in main method
		//Added:      make(map[string]bool),
	}

	return web, nil
}

func setQueryParameterMap(queryParameterMap map[string]string, querySlice []string) map[string]string {
	for _, q := range querySlice {
		q = strings.TrimSuffix(q, "\r")
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		} else if !strings.Contains(q, "=") {
			msg := fmt.Sprintf("Specified parameter %s doesn't contain a = and will be skipped\n", q)
			Print(msg, Yellow)
			continue
		} else {
			query := strings.SplitN(q, "=", 2)
			// ok is true, if a query already is set
			val, ok := queryParameterMap[query[0]]
			if ok {
				msg := fmt.Sprintf("Overwriting %s=%s with %s=%s\n", query[0], val, query[0], query[1])
				Print(msg, NoColor)
			}
			queryParameterMap[query[0]] = query[1]
		}
	}

	return queryParameterMap
}

func addDomain(x string, domain string) string {
	if strings.HasPrefix(x, "#") || strings.HasPrefix(x, "mailto:") {
		return ""
	}
	if strings.HasPrefix(x, "https://"+domain) || strings.HasPrefix(x, "http://"+domain) {
		return x
	} else if strings.HasPrefix(x, "//") {
		return Config.Website.Domain + x[1:]
	} else if !strings.HasPrefix(x, "http://") && !strings.HasPrefix(x, "https://") {
		if strings.HasPrefix(x, "/") {
			return Config.Website.Domain + x
		}
		return Config.Website.Domain + "/" + x
	} else {
		for i, d := range Config.RecDomains {
			if Config.RecDomains[i] == "" {
				continue
			}
			if strings.HasPrefix(x, "https://"+d) || strings.HasPrefix(x, "http://"+d) {
				return x
			}
		}

		msg := fmt.Sprintf("%s doesn't have %s as domain\n", x, domain)
		PrintVerbose(msg, NoColor, 1)

		return ""
	}
}

func checkRecInclude(x string, recInclude string) bool {
	for _, inc := range strings.Split(recInclude, " ") {
		// remove spaces and skip if someone used multiple spaces instead of one
		if inc == "" {
			continue
		}
		if strings.Contains(x, inc) {
			return true
		}
	}
	return false
}

func addUrl(urls []string, url string, added map[string]bool, excluded map[string]bool) []string {
	url = addDomain(url, Config.Website.Url.Hostname())

	if url != "" {
		// Check if url isnt added yet and if it satisfies RecInclude (=contains it)
		if excluded[url] {
			msg := fmt.Sprintf("Skipped to add %s to the queue, because it is on the exclude list\n", url)
			PrintVerbose(msg, NoColor, 1)
		} else if added[url] {
			msg := fmt.Sprintf("Skipped to add %s to the queue, because it was already added\n", url)
			PrintVerbose(msg, NoColor, 2)
		} else if Config.RecInclude == "" || checkRecInclude(url, Config.RecInclude) {
			urls = append(urls, url)
			added[url] = true
		} else {
			msg := fmt.Sprintf("Skipped to add %s to the queue, because it doesn't satisfy RecInclude\n", url)
			PrintVerbose(msg, NoColor, 1)
		}
	}

	return urls
}

func CrawlUrls(added map[string]bool, excluded map[string]bool) []string {
	bodyReader := strings.NewReader(Config.Website.Body)
	tokenizer := html.NewTokenizer(bodyReader)

	var urls []string

	eof := false
	for !eof {
		tokentype := tokenizer.Next()

		switch tokentype {
		case html.StartTagToken, html.SelfClosingTagToken:

			token := tokenizer.Token()

			if token.Data == "a" || token.Data == "link" {
				for _, a := range token.Attr {
					if a.Key == "href" {
						urls = addUrl(urls, a.Val, added, excluded)
						break
					}
				}
			} else if token.Data == "script" {
				for _, a := range token.Attr {
					if a.Key == "src" {
						urls = addUrl(urls, a.Val, added, excluded)
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

	if h := Config.Website.Headers.Get("Location"); h != "" {
		urls = addUrl(urls, h, added, excluded)
	}

	return urls
}
