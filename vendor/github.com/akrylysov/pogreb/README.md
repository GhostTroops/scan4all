<p align="center"><img src="https://akrylysov.github.io/pogreb/logo.svg" width="300"></p>

# Pogreb
[![Docs](https://godoc.org/github.com/akrylysov/pogreb?status.svg)](https://pkg.go.dev/github.com/akrylysov/pogreb)
[![Build Status](https://github.com/akrylysov/pogreb/actions/workflows/test.yaml/badge.svg?branch=master)](https://github.com/akrylysov/pogreb/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/akrylysov/pogreb)](https://goreportcard.com/report/github.com/akrylysov/pogreb)
[![Codecov](https://codecov.io/gh/akrylysov/pogreb/branch/master/graph/badge.svg)](https://codecov.io/gh/akrylysov/pogreb)

Pogreb is an embedded key-value store for read-heavy workloads written in Go.

## Key characteristics

- 100% Go.
- Optimized for fast random lookups and infrequent bulk inserts.
- Can store larger-than-memory data sets.
- Low memory usage.
- All DB methods are safe for concurrent use by multiple goroutines.

## Installation

```sh
$ go get -u github.com/akrylysov/pogreb
```

## Usage

### Opening a database

To open or create a new database, use the `pogreb.Open()` function:

```go
package main

import (
	"log"

	"github.com/akrylysov/pogreb"
)

func main() {
    db, err := pogreb.Open("pogreb.test", nil)
    if err != nil {
        log.Fatal(err)
        return
    }	
    defer db.Close()
}
```

### Writing to a database

Use the `DB.Put()` function to insert a new key-value pair:

```go
err := db.Put([]byte("testKey"), []byte("testValue"))
if err != nil {
	log.Fatal(err)
}
```

### Reading from a database

To retrieve the inserted value, use the `DB.Get()` function:

```go
val, err := db.Get([]byte("testKey"))
if err != nil {
	log.Fatal(err)
}
log.Printf("%s", val)
```

### Iterating over items

To iterate over items, use `ItemIterator` returned by `DB.Items()`:

```go
it := db.Items()
for {
    key, val, err := it.Next()
    if err == pogreb.ErrIterationDone {
    	break
    }
    if err != nil { 
        log.Fatal(err)
    }
    log.Printf("%s %s", key, val)
}
```

## Performance

The benchmarking code can be found in the [pogreb-bench](https://github.com/akrylysov/pogreb-bench) repository.

Results of read performance benchmark of pogreb, goleveldb, bolt and badgerdb
on DigitalOcean 8 CPUs / 16 GB RAM / 160 GB SSD + Ubuntu 16.04.3 (higher is better):

<p align="center"><img src="https://akrylysov.github.io/pogreb/read-bench.png" width="609"></p>

## Internals

[Design document](/docs/design.md).
