package filekv

import "math"

const Separator = ";;;"

type Options struct {
	Path     string
	Dedupe   bool
	Compress bool
	MaxItems uint
	FPRatio  float64
	Cleanup  bool
}

type Stats struct {
	NumberOfAddedItems uint
	NumberOfDupedItems uint
	NumberOfItems      uint
}

var DefaultOptions Options = Options{
	Dedupe:   true,
	Compress: false,
	MaxItems: math.MaxInt32,
	FPRatio:  0.0000001,
	Cleanup:  true,
}
