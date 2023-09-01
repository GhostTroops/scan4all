# ratelimit

[![License](https://img.shields.io/github/license/projectdiscovery/ratelimit)](LICENSE.md)
![Go version](https://img.shields.io/github/go-mod/go-version/projectdiscovery/ratelimit?filename=go.mod)
[![Release](https://img.shields.io/github/release/projectdiscovery/ratelimit)](https://github.com/projectdiscovery/ratelimit/releases/)
[![Checks](https://github.com/projectdiscovery/ratelimit/actions/workflows/build-test.yml/badge.svg)](https://github.com/projectdiscovery/ratelimit/actions/workflows/build-test.yml)
[![GoDoc](https://pkg.go.dev/badge/projectdiscovery/ratelimit)](https://pkg.go.dev/github.com/projectdiscovery/ratelimit)

A Golang rate limit implementation which allows burst of request during the defined duration.


### Differences with 'golang.org/x/time/rate#Limiter'

The original library i.e `golang.org/x/time/rate` implements classic **token bucket** algorithm allowing a burst of tokens and a refill that happens at a specified ratio by one unit at a time whereas this implementation is a variant  that allows a burst of tokens just like "the token bucket" algorithm, but the refill happens entirely at the defined ratio.

This allows scanners to respect maximum defined rate limits, pause until the allowed interval hits, and then process again at maximum speed. The original library slowed down requests according to the refill ratio.

## Example

An Example showing usage of ratelimit as a library is specified below:

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

func main() {

	// create a rate limiter by passing context, max tasks/requests , time interval
	limiter := ratelimit.New(context.Background(), 5, time.Duration(10*time.Second))

	save := time.Now()

	for i := 0; i < 10; i++ {
		// run limiter.Take() method before each task
		limiter.Take()
		fmt.Printf("Task %v completed after %v\n", i, time.Since(save))
	}

	/*
		Output:
		Task 0 completed after 4.083µs
		Task 1 completed after 111.416µs
		Task 2 completed after 118µs
		Task 3 completed after 121.083µs
		Task 4 completed after 124.583µs
		Task 5 completed after 10.001356375s
		Task 6 completed after 10.001524791s
		Task 7 completed after 10.001537583s
		Task 8 completed after 10.001542708s
		Task 9 completed after 10.001548666s
	*/
}
```
