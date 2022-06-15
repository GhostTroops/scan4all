# simhash

`simhash` is a [Go](http://golang.org/) implementation of Charikar's [simhash](http://www.cs.princeton.edu/courses/archive/spring04/cos598B/bib/CharikarEstim.pdf) algorithm.

`simhash` is a hash with the useful property that similar documents produce similar hashes.
Therefore, if two documents are similar, the Hamming-distance between the simhash of the
documents will be small.

This package currently just implements the simhash algorithm. Future work will make use of this
package to enable quickly identifying near-duplicate documents within a large collection of
documents.

# Installation

```
go get github.com/mfonda/simhash
```

# Usage

Using `simhash` first requires tokenizing a document into a set of features (done through the
`FeatureSet` interface). This package provides an implementation, `WordFeatureSet`, which breaks
tokenizes the document into individual words. Better results are possible here, and future work
will go towards this.

Example usage:

```go
package main

import (
	"fmt"
	"github.com/mfonda/simhash"
)

func main() {
	var docs = [][]byte{
		[]byte("this is a test phrase"),
		[]byte("this is a test phrass"),
		[]byte("foo bar"),
	}

	hashes := make([]uint64, len(docs))
	for i, d := range docs {
		hashes[i] = simhash.Simhash(simhash.NewWordFeatureSet(d))
		fmt.Printf("Simhash of %s: %x\n", d, hashes[i])
	}

	fmt.Printf("Comparison of `%s` and `%s`: %d\n", docs[0], docs[1], simhash.Compare(hashes[0], hashes[1]))
	fmt.Printf("Comparison of `%s` and `%s`: %d\n", docs[0], docs[2], simhash.Compare(hashes[0], hashes[2]))
}
```

Output:

```
Simhash of this is a test phrase: 8c3a5f7e9ecb3f35
Simhash of this is a test phrass: 8c3a5f7e9ecb3f21
Simhash of foo bar: d8dbe7186bad3db3
Comparison of `this is a test phrase` and `this is a test phrass`: 2
Comparison of `this is a test phrase` and `foo bar`: 29
```
