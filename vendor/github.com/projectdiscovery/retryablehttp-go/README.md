# retryablehttp

Heavily inspired from [https://github.com/hashicorp/go-retryablehttp](https://github.com/hashicorp/go-retryablehttp).

### Usage

Example of using `retryablehttp` in Go Code is available in [examples](examples/) folder
Examples of using Nuclei From Go Code to run templates on targets are provided in the examples folder.


### url encoding and parsing issues

`retryablehttp.Request` by default handles some [url encoding and parameters issues](https://github.com/projectdiscovery/utils/blob/main/url/README.md). since `http.Request` internally uses `url.Parse()` to parse url specified in request it creates some inconsistencies for below urls and other non-RFC compilant urls 

```
// below urls are either normalized or returns error when used in `http.NewRequest()`
https://scanme.sh/%invalid
https://scanme.sh/w%0d%2e/
scanme.sh/with/path?some'param=`'+OR+ORDER+BY+1--
```
All above mentioned cases are handled internally in `retryablehttp`.

### Note
It is not recommended to update `url.URL` instance of `Request` once a new request is created (ex `req.URL.Path = xyz`) due to internal logic of urls.
In any case if it is not possible to follow above point due to some reason helper methods are available to reflect such changes

- `Request.Update()` commits any changes made to query parameters (ex: `Request.URL.Query().Add(x,y)`)
