# networkpolicy

[![License](https://img.shields.io/github/license/projectdiscovery/networkpolicy)](LICENSE.md)
![Go version](https://img.shields.io/github/go-mod/go-version/projectdiscovery/networkpolicy?filename=go.mod)
[![Release](https://img.shields.io/github/release/projectdiscovery/networkpolicy)](https://github.com/projectdiscovery/networkpolicy/releases/)
[![Checks](https://github.com/projectdiscovery/networkpolicy/actions/workflows/build-test.yml/badge.svg)](https://github.com/projectdiscovery/networkpolicy/actions/workflows/build-test.yml)
[![GoDoc](https://pkg.go.dev/badge/projectdiscovery/networkpolicy)](https://pkg.go.dev/github.com/projectdiscovery/networkpolicy)



The package acts as an embeddable configurable container handling allow/deny verdicts over a series of conditions including
- IPs
- CIDRs
- Ports
- Schemes (eg `https, http, ftp`)

## General usage as allow/deny
The following program prevents the http client to follow targets belonging to the deny list:

Example - General allow/deny list
```go
package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/projectdiscovery/networkpolicy"
)

func main() {
	var npOptions networkpolicy.Options
	// deny connections to localhost
	npOptions.DenyList = append(npOptions.DenyList, "127.0.0.0/8")

	np, err := networkpolicy.New(npOptions)
	if err != nil {
		log.Fatal(err)
	}

	customRedirectHandler := func(req *http.Request, via []*http.Request) error {
		// if at least one address is valid we follow the redirect
		if _, ok := np.ValidateHost(req.Host); ok {
			return nil
		}
		return errors.New("redirected to a forbidden target")
	}

	client := &http.Client{
		CheckRedirect: customRedirectHandler,
	}
	req, err := http.NewRequest(http.MethodGet, "http://yourtarget", nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(resp)
}
```

## ASN-based allow/deny

`networkpolicy` intentionally does not perform ASN→CIDR resolution itself — that responsibility belongs to [`asnmap`](https://github.com/projectdiscovery/asnmap), where BGP data, caching, and network errors are already handled. To restrict (or allow) traffic by ASN, expand it to CIDRs upstream and feed them into the existing `AllowList`/`DenyList`:

```go
package main

import (
	"log"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/networkpolicy"
)

func main() {
	client, err := asnmap.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	var denyCIDRs []string
	for _, asn := range []string{"AS13335", "AS15169"} {
		resp, err := client.GetData(asn)
		if err != nil {
			log.Fatal(err)
		}
		nets, err := asnmap.GetCIDR(resp)
		if err != nil {
			log.Fatal(err)
		}
		for _, n := range nets {
			denyCIDRs = append(denyCIDRs, n.String())
		}
	}

	np, err := networkpolicy.New(networkpolicy.Options{DenyList: denyCIDRs})
	if err != nil {
		log.Fatal(err)
	}
	_ = np
}
```