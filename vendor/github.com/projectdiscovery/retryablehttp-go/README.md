# retryablehttp

Heavily inspired from [https://github.com/hashicorp/go-retryablehttp](https://github.com/hashicorp/go-retryablehttp).

### Usage

```go
package main

import (
	"fmt"
	"io/ioutil"

	"github.com/projectdiscovery/retryablehttp-go"
)

func main() {
	opts := retryablehttp.DefaultOptionsSpraying
	// opts := retryablehttp.DefaultOptionsSingle // use single options for single host
	client := retryablehttp.NewClient(opts)
	resp, err := client.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Data: %v\n", string(data))
}
```
