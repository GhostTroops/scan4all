# Overview

A lightweight observable lib. Go channel doesn't support unlimited buffer size,
it's a pain to decide what size to use, this lib will handle it dynamically.

- unlimited buffer size
- one publisher to multiple subscribers
- thread-safe
- subscribers never block each other
- stable event order

## Examples

See [examples_test.go](examples_test.go).

## Benchmark

```txt
goos: darwin
goarch: amd64
pkg: github.com/ysmood/goob
cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
BenchmarkPublish-12    	 7493547	       143.9 ns/op	      86 B/op	       0 allocs/op
BenchmarkConsume-12    	 4258910	       275.5 ns/op	       0 B/op	       0 allocs/op
```
