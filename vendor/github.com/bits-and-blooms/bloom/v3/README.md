Bloom filters
-------------
[![Test](https://github.com/bits-and-blooms/bloom/actions/workflows/test.yml/badge.svg)](https://github.com/bits-and-blooms/bloom/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/bits-and-blooms/bloom)](https://goreportcard.com/report/github.com/bits-and-blooms/bloom)
[![Go Reference](https://pkg.go.dev/badge/github.com/bits-and-blooms/bloom.svg)](https://pkg.go.dev/github.com/bits-and-blooms/bloom)

A Bloom filter is a concise/compressed representation of a set, where the main
requirement is to make membership queries; _i.e._, whether an item is a
member of a set. A Bloom filter will always correctly report the presence
of an element in the set when the element is indeed present. A Bloom filter 
can use much less storage than the original set, but it allows for some 'false positives':
it may sometimes report that an element is in the set whereas it is not.

When you construct, you need to know how many elements you have (the desired capacity), and what is the desired false positive rate you are willing to tolerate. A common false-positive rate is 1%. The
lower the false-positive rate, the more memory you are going to require. Similarly, the higher the
capacity, the more memory you will use.
You may construct the Bloom filter capable of receiving 1 million elements with a false-positive
rate of 1% in the following manner. 

```Go
    filter := bloom.NewWithEstimates(1000000, 0.01) 
```

You should call `NewWithEstimates` conservatively: if you specify a number of elements that it is
too small, the false-positive bound might be exceeded. A Bloom filter is not a dynamic data structure:
you must know ahead of time what your desired capacity is.

Our implementation accepts keys for setting and testing as `[]byte`. Thus, to
add a string item, `"Love"`:

```Go
    filter.Add([]byte("Love"))
```

Similarly, to test if `"Love"` is in bloom:

```Go
    if filter.Test([]byte("Love"))
```

For numerical data, we recommend that you look into the encoding/binary library. But, for example, to add a `uint32` to the filter:

```Go
    i := uint32(100)
    n1 := make([]byte, 4)
    binary.BigEndian.PutUint32(n1, i)
    filter.Add(n1)
```

Discussion here: [Bloom filter](https://groups.google.com/d/topic/golang-nuts/6MktecKi1bE/discussion)

Godoc documentation: https://pkg.go.dev/github.com/bits-and-blooms/bloom

## Installation

```bash
go get -u github.com/bits-and-blooms/bloom/v3
```

## Contributing

If you wish to contribute to this project, please branch and issue a pull request against master ("[GitHub Flow](https://guides.github.com/introduction/flow/)")

This project includes a Makefile that allows you to test and build the project with simple commands.
To see all available options:
```bash
make help
```

## Running all tests

Before committing the code, please check if it passes all tests using (note: this will install some dependencies):
```bash
make deps
make qa
```

## Design

A Bloom filter has two parameters: _m_, the number of bits used in storage, and _k_, the number of hashing functions on elements of the set. (The actual hashing functions are important, too, but this is not a parameter for this implementation). A Bloom filter is backed by a [BitSet](https://github.com/bits-and-blooms/bitset); a key is represented in the filter by setting the bits at each value of the  hashing functions (modulo _m_). Set membership is done by _testing_ whether the bits at each value of the hashing functions (again, modulo _m_) are set. If so, the item is in the set. If the item is actually in the set, a Bloom filter will never fail (the true positive rate is 1.0); but it is susceptible to false positives. The art is to choose _k_ and _m_ correctly.

In this implementation, the hashing functions used is [murmurhash](https://github.com/spaolacci/murmur3), a non-cryptographic hashing function.


Given the particular hashing scheme, it's best to be empirical about this. Note
that estimating the FP rate will clear the Bloom filter.
