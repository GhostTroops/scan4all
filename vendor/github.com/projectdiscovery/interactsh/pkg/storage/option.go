package storage

import "time"

type Options struct {
	DbPath      string
	EvictionTTL time.Duration
	MaxSize     int
}

func (options *Options) UseDisk() bool {
	return options.DbPath != ""
}

var DefaultOptions = Options{
	MaxSize: 2500000,
}
