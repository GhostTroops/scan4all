Aurora
======

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/logrusorgru/aurora/v3?tab=doc)
[![Unlicense](https://img.shields.io/badge/license-unlicense-blue.svg)](http://unlicense.org/)
[![Build Status](https://github.com/logrusorgru/aurora/workflows/build/badge.svg)](https://github.com/logrusorgru/aurora/actions?workflow=build)
[![Coverage Status](https://coveralls.io/repos/github/logrusorgru/aurora/badge.svg?branch=master)](https://coveralls.io/github/logrusorgru/aurora?branch=master)
[![GoReportCard](https://goreportcard.com/badge/logrusorgru/aurora)](https://goreportcard.com/report/logrusorgru/aurora)

Ultimate ANSI colors for Golang. The package supports Printf/Sprintf etc.


![aurora logo](https://github.com/logrusorgru/aurora/blob/master/gopher_aurora.png)

# TOC

- [Installation](#installation)
- [Usage](#usage)
  + [Simple](#simple)
  + [Printf](#printf)
  + [aurora.Sprintf](#aurorasprintf)
  + [Enable/Disable colors](#enabledisable-colors)
  + [Hyperlinks, default colorizer, and configurations](#hyperlinks-default-colorizer-and-configurations)
- [Chains](#chains)
- [Colorize](#colorize)
- [Grayscale](#grayscale)
- [8-bit colors](#8-bit-colors)
- [Supported Colors & Formats](#supported-colors--formats)
  + [All colors](#all-colors)
  + [Standard and bright colors](#standard-and-bright-colors)
  + [Formats are likely supported](#formats-are-likely-supported)
  + [Formats are likely unsupported](#formats-are-likely-unsupported)
- [Limitations](#limitations)
  + [Windows](#windows)
  + [TTY](#tty)
- [Licensing](#licensing)

# Installation

##### Version 1.x

Using gopkg.in.

```
go get -u gopkg.in/logrusorgru/aurora.v1
```

##### Version 2.x

```
go get -u github.com/logrusorgru/aurora
```

##### Go modules support, version v3+

Get
```
go get -u github.com/logrusorgru/aurora/v3
```

The v3 was introduced to support `go.mod` and leave previous import paths as is.
Currently, there is no changes between them (excluding the importpath's /v3 tail).

##### The latest version

```
go get -u github.com/logrusorgru/aurora/v4
```

With hyperlinks.

# Test

```
go test -cover -race github.com/logrusorgru/aurora/v4
```

Replace the import path with your, if it's different.

# Usage

### Simple

```go
package main

import (
	"fmt"

	"github.com/logrusorgru/aurora/v4"
)

func main() {
	fmt.Println("Hello,", aurora.Magenta("Aurora"))
	fmt.Println(aurora.Bold(aurora.Cyan("Cya!")))
}

```

![simple png](https://github.com/logrusorgru/aurora/blob/master/simple.png)

### Printf

```go
package main

import (
	"fmt"

	"github.com/logrusorgru/aurora/v4"
)

func main() {
	fmt.Printf("Got it %d times\n", aurora.Green(1240))
	fmt.Printf("PI is %+1.2e\n", aurora.Cyan(3.14))
}

```

![printf png](https://github.com/logrusorgru/aurora/blob/master/printf.png)

### aurora.Sprintf

```go
package main

import (
	"fmt"

	"github.com/logrusorgru/aurora/v4"
)

func main() {
	fmt.Println(aurora.Sprintf(aurora.Magenta("Got it %d times"), aurora.Green(1240)))
}

```

![sprintf png](https://github.com/logrusorgru/aurora/blob/master/sprintf.png)

### Enable/Disable colors

```go
package main

import (
	"fmt"
	"flag"

	"github.com/logrusorgru/aurora/v4"
)

// colorizer
var au *aurora.Aurora

var colors = flag.Bool("colors", false, "enable or disable colors")

func init() {
	flag.Parse()
	au = aurora.New(WithColors(*colors))
}

func main() {
	// use colorizer
	fmt.Println(au.Green("Hello"))
}

```
Without flags:
![disable png](https://github.com/logrusorgru/aurora/blob/master/disable.png)

With `-colors` flag:
![enable png](https://github.com/logrusorgru/aurora/blob/master/enable.png)

### Hyperlinks, default colorizer, and configurations

[Hyperlinks feature description](https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda).

Add a red hyperlinks with text "Example" that is referencing to
http://example.com.

```go
package main

import (
	"flag"
	"fmt"

	"github.com/logrusorgru/aurora/v4"
)

func main() {
	var conf = aurora.NewConfig()
	conf.AddFlags(flag.CommandLine, "prefix.")
	flag.Parse()

	aurora.DefaultColorizer = aurora.New(conf.Options()...) // set global

	fmt.Println(aurora.Red("Example").Hyperlink("http://example.com/"))
}
```
Depending flags:
![depending flags png](https://github.com/logrusorgru/aurora/blob/master/aurora_hyperlinks_flags.png)
![depending flags gif](https://github.com/logrusorgru/aurora/blob/master/aurora_hyperlinks.gif)

# Chains

The following samples are equal

```go
x := aurora.BgMagenta(aurora.Bold(aurora.Red("x")))
```

```go
x := aurora.Red("x").Bold().BgMagenta()
```

The second is more readable

# Colorize

There is `Colorize` function that allows to choose some colors and
format from a side

```go

func getColors() Color {
	// some stuff that returns appropriate colors and format
}

// [...]

func main() {
	fmt.Println(aurora.Colorize("Greeting", getColors()))
}

```
Less complicated example

```go
x := aurora.Colorize("Greeting", GreenFg|GrayBg|BoldFm)
```

Unlike other color functions and methods (such as Red/BgBlue etc)
a `Colorize` clears previous colors

```go
x := aurora.Red("x").Colorize(BgGreen) // will be with green background only
```

# Grayscale

```go
fmt.Println("  ",
	aurora.Gray(1-1, " 00-23 ").BgGray(24-1),
	aurora.Gray(4-1, " 03-19 ").BgGray(20-1),
	aurora.Gray(8-1, " 07-15 ").BgGray(16-1),
	aurora.Gray(12-1, " 11-11 ").BgGray(12-1),
	aurora.Gray(16-1, " 15-07 ").BgGray(8-1),
	aurora.Gray(20-1, " 19-03 ").BgGray(4-1),
	aurora.Gray(24-1, " 23-00 ").BgGray(1-1),
)
```

![grayscale png](https://github.com/logrusorgru/aurora/blob/master/aurora_grayscale.png)  

# 8-bit colors

Methods `Index` and `BgIndex` implements 8-bit colors.

| Index/BgIndex  |    Meaning      | Foreground | Background |
| -------------- | --------------- | ---------- | ---------- |
|      0-  7     | standard colors |   30- 37   |   40- 47   |
|      8- 15     | bright colors   |   90- 97   |  100-107   |
|     16-231     | 216 colors      |   38;5;n   |   48;5;n   |
|    232-255     | 24 grayscale    |   38;5;n   |   48;5;n   |

Example

```go
package main

import (
	"fmt"
	"github.com/logrusorgru/aurora"
)

func main() {
	for i := uint8(16); i <= 231; i++ {
		fmt.Println(i, aurora.Index(i, "pew-pew"), aurora.BgIndex(i, "pew-pew"))
	}
}
```

# Supported colors & formats

- formats
  + bold (1)
  + faint (2)
  + doubly-underline (21)
  + fraktur (20)
  + italic (3)
  + underline (4)
  + slow blink (5)
  + rapid blink (6)
  + reverse video (7)
  + conceal (8)
  + crossed out (9)
  + framed (51)
  + encircled (52)
  + overlined (53)
- background and foreground colors, including bright
  + black
  + red
  + green
  + yellow (brown)
  + blue
  + magenta
  + cyan
  + white
  + 24 grayscale colors
  + 216 8-bit colors

### All colors

![linux png](https://github.com/logrusorgru/aurora/blob/master/aurora_colors_black.png)  
![white png](https://github.com/logrusorgru/aurora/blob/master/aurora_colors_white.png)  

### Standard and bright colors

![linux black standard png](https://github.com/logrusorgru/aurora/blob/master/aurora_black_standard.png)
![linux white standard png](https://github.com/logrusorgru/aurora/blob/master/aurora_white_standard.png)

### Formats are likely supported

![formats supported gif](https://github.com/logrusorgru/aurora/blob/master/aurora_formats.gif)

### Formats are likely unsupported

![formats rarely supported png](https://github.com/logrusorgru/aurora/blob/master/aurora_rarely_supported.png)

# Limitations

There is no way to represent `%T` and `%p` with colors using
a standard approach

```go
package main

import (
	"fmt"

	"github.com/logrusorgru/aurora"
)

func main() {
	var (
		r = aurora.Red("red")
		i int
	)
	fmt.Printf("%T %p\n", r, aurora.Green(&i))
}
```

Output will be without colors

```
aurora.value %!p(aurora.value={0xc42000a310 768 0})
```

The obvious workaround is `Red(fmt.Sprintf("%T", some))`

### Windows

The Aurora provides ANSI colors only, so there is no support for Windows. That said, there are workarounds available.
Check out these comments to learn more:

- [Using go-colorable](https://github.com/logrusorgru/aurora/issues/2#issuecomment-299014211).
- [Using registry for Windows 10](https://github.com/logrusorgru/aurora/issues/10#issue-476361247).

### TTY

The Aurora has no internal TTY detectors by design. Take a look
 [this comment](https://github.com/logrusorgru/aurora/issues/2#issuecomment-299030108) if you want turn
on colors for a terminal only, and turn them off for a file.

### Licensing

Copyright &copy; 2016-2022 The Aurora Authors. This work is free.
It comes without any warranty, to the extent permitted by applicable
law. You can redistribute it and/or modify it under the terms of the
the Unlicense. See the LICENSE file for more details.
