# cdncheck
Helper library that checks if a given IP belongs to known CDN ranges (akamai, cloudflare, incapsula, sucuri and leaseweb).
The library can be used by importing `github.com/projectdiscovery/cdncheck`. here follows a basic example:

```go
package main

import (
    "log"
    "net"
    "github.com/projectdiscovery/cdncheck"
)

func main() {
    // uses projectdiscovery endpoint with cached data to avoid ip ban
    // Use cdncheck.New() if you want to scrape each endpoint (don't do it too often or your ip can be blocked)
    client, err := cdncheck.NewWithCache()
    if err != nil {
        log.Fatal(err)
    }
    if found, err := client.Check(net.ParseIP("173.245.48.12")); found && err == nil {
        log.Println("ip is part of cdn")
    }
}
```