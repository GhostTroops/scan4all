[![GoDoc](https://godoc.org/github.com/hbakhtiyor/strsim?status.svg)](https://godoc.org/github.com/hbakhtiyor/strsim) [![Build Status](https://travis-ci.com/hbakhtiyor/strsim.svg?branch=master)](https://travis-ci.org/hbakhtiyor/strsim) [![Go Report Card](https://goreportcard.com/badge/github.com/hbakhtiyor/strsim)](https://goreportcard.com/report/github.com/hbakhtiyor/strsim)

strsim
=================

Finds degree of similarity between two strings, based on [Dice's Coefficient](http://en.wikipedia.org/wiki/S%C3%B8rensen%E2%80%93Dice_coefficient).

## Table of Contents

* [Usage](#usage)
* [API](#api)
    * [Compare(a, b string) float64](#comparea-b-string-float64)
        * [Arguments](#arguments)
        * [Returns](#returns)
        * [Examples](#examples)
    * [FindBestMatch(s string, targets []string) *MatchResult](#findbestmatchs-string-targets-string-matchresult)
        * [Arguments](#arguments-1)
        * [Returns](#returns-1)
        * [Examples](#examples-1)
* [Benchmark](#benchmark)
   * [Hardware used](#hardware-used)
   * [Version](#version)
* [Credit](#credit)


## Usage
Install using:

```shell
go get -u github.com/hbakhtiyor/strsim
```

In your code:

```go
import "github.com/hbakhtiyor/strsim"

similarity := strsim.Compare("healed", "sealed")

matches := strsim.FindBestMatch("healed", []string{"edward", "sealed", "theatre")
```
## API

Requiring the module gives an object with two methods:

### Compare(a, b string) float64

Returns a fraction between 0 and 1, which indicates the degree of similarity between the two strings. 0 indicates completely different strings, 1 indicates identical strings. The comparison is case-sensitive.

##### Arguments
  
1. a (string): The first string
2. b (string): The second string
  
Order does not make a difference.
  
##### Returns
  
(float64): A fraction from 0 to 1, both inclusive. Higher number indicates more similarity.

##### Examples
  
```go
strsim.Compare("healed", "sealed")
// → 0.8

strsim.Compare("Olive-green table for sale, in extremely good condition.", 
  "For sale: table in very good  condition, olive green in colour.")
// → 0.6060606060606061

strsim.Compare("Olive-green table for sale, in extremely good condition.", 
  "For sale: green Subaru Impreza, 210,000 miles")
// → 0.2558139534883721

strsim.Compare("Olive-green table for sale, in extremely good condition.", 
  "Wanted: mountain bike with at least 21 gears.")
// → 0.1411764705882353
```

### FindBestMatch(s string, targets []string) *MatchResult

Compares `s` against each string in `targets`.

##### Arguments

1. s (string): The string to match each target string against.
2. targets ([]string): Each string in this array will be matched against the main string.

##### Returns
(MatchResult): An object with a `Matches` field, which gives a similarity score for each target string, a `BestMatch` field, which specifies which target string was most similar to the main string, and a `BestMatchIndex` field, which specifies the index of the `BestMatch` in the `targets` array.

##### Examples
```go
strsim.FindBestMatch("Olive-green table for sale, in extremely good condition.", []string{
  "For sale: green Subaru Impreza, 210,000 miles", 
  "For sale: table in very good condition, olive green in colour.", 
  "Wanted: mountain bike with at least 21 gears.",
});
// → 
MatchResult {
  Matches: []Match {
    { Target: "For sale: green Subaru Impreza, 210,000 miles",
      Score: 0.2558139534883721 },
    { Target: "For sale: table in very good condition, olive green in colour.",
      Score: 0.6060606060606061 },
    { Target: "Wanted: mountain bike with at least 21 gears.",
      Score: 0.1411764705882353 } },
  BestMatch: Match
    { Target: "For sale: table in very good condition, olive green in colour.",
      Score: 0.6060606060606061 },
  BestMatchIndex: 1 
}
```

## Benchmark

```
BenchmarkCompare-4         	   20000	     82479 ns/op	   15921 B/op	      51 allocs/op
BenchmarkFindBestMatch-4   	   30000	     60800 ns/op	   11707 B/op	      41 allocs/op
BenchmarkSortedByScore-4   	 2000000	       638 ns/op	     128 B/op	       4 allocs/op
```

##### Hardware used

* Intel® Core™ i3-2310M CPU @ 2.10GHz × 4
* 4Gb RAM

##### Version

* Go 1.11.2
* Ubuntu 18.04.01 LTS x86_64 OS
* 4.15.0-39-generic kernel

## Credit
https://github.com/aceakash/string-similarity
