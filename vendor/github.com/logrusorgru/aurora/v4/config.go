//
// Copyright (c) 2016-2022 The Aurora Authors. All rights reserved.
// This program is free software. It comes without any warranty,
// to the extent permitted by applicable law. You can redistribute
// it and/or modify it under the terms of the Unlicense. See LICENSE
// file for more details or see below.
//

//
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
//

package aurora

import "flag"

// Config represents configurations of a colorizer.
type Config struct {
	// Colors feature. Enable colors if true.
	Colors bool `json:"colors" yaml:"colors" toml:"colors" mapstructure:"colors"`
	// Hyperlinks feature. Enable hyperlinks if true.
	Hyperlinks bool `json:"hyperlinks" yaml:"hyperlinks" toml:"hyperlinks" mapstructure:"hyperlinks"`
}

// NewConfig returns new default Config.
func NewConfig() (conf Config) {
	conf.Colors = true
	conf.Hyperlinks = true
	return
}

// AddFlags to given *flag.FlagSet. The prefix used as prefix for flags.
// It may be used to parse commandline flags. For example
//
//	var conf Config
//	conf.AddFlags(flag.CommandLine, "colors.")
//	flag.Parse()
//
// for a main package, and use with flags commandline flags,
//
//	go run main.go -colors.colors -colors.hyperlinks
//
// to enable or disable features. A colorizer can be created, for example,
//
//	var colorizer = New(conf.Options()...)
func (c *Config) AddFlags(fset *flag.FlagSet, prefix string) {
	fset.BoolVar(&c.Colors,
		prefix+"colors",
		c.Colors,
		"enable colors")
	fset.BoolVar(&c.Hyperlinks,
		prefix+"hyperlinks",
		c.Hyperlinks,
		"enable hyperlinks")
}

// Apply given options for the Config.
func (c *Config) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}

// Options by the Config.
func (c *Config) Options() (opts []Option) {
	return []Option{
		WithColors(c.Colors),
		WithHyperlinks(c.Hyperlinks),
	}
}

func (c *Config) colorConfig() (cc colorConfig) {
	if c.Colors {
		cc |= colorPin
	}
	if c.Hyperlinks {
		cc |= hyperlinksPin
	}
	return
}

// An Option function.
type Option func(*Config)

// WithColors is an Option that used to enable or disable colors.
func WithColors(t bool) Option {
	return func(c *Config) {
		c.Colors = t
	}
}

// WithHyperlinks is an Option that used to enable or disable links.
func WithHyperlinks(t bool) Option {
	return func(c *Config) {
		c.Hyperlinks = t
	}
}
