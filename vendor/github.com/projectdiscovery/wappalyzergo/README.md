# Wappalyzergo

A high performance port of the Wappalyzer Technology Detection Library to Go. Inspired by [Webanalyze](https://github.com/rverton/webanalyze).

Uses data from 
- https://github.com/enthec/webappanalyzer
- https://github.com/HTTPArchive/wappalyzer

## Features

- Very simple and easy to use, with clean codebase.
- Normalized regexes + auto-updating database of wappalyzer fingerprints.
- Optimized for performance: parsing HTML manually for best speed.

### Using *go install*

```sh
go install -v github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest
```

After this command *wappalyzergo* library source will be in your current go.mod.

## Example
Usage Example:

``` go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
	resp, err := http.DefaultClient.Get("https://www.hackerone.com")
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body) // Ignoring error for example

	wappalyzerClient, err := wappalyzer.New()
	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
	fmt.Printf("%v\n", fingerprints)

	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]
}
```

### Optional runtime detection

`Fingerprint` still uses only the response headers and body. Use
`FingerprintWithRuntime` to also check JavaScript properties, the rendered DOM,
and script content. The optional `headless` adapter works with a Rod page that
the caller has already loaded. The caller remains responsible for launching,
navigating, and closing the browser.

```go
collector := headless.New(page)

fingerprints, err := wappalyzerClient.FingerprintWithRuntime(
	ctx, resp.Header, data,
	wappalyzer.RuntimeOptions{
		Collector: collector,
		Timeout:   10 * time.Second,
	},
)
```

If runtime collection returns an error, the result still includes passive
matches and any matches found before the failure. Other browser integrations
can implement `wappalyzer.RuntimeCollector` without importing the Rod adapter.
