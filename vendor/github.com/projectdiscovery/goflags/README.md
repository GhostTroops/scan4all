# goflags

[![License](https://img.shields.io/github/license/projectdiscovery/goflags)](LICENSE.md)
![Go version](https://img.shields.io/github/go-mod/go-version/projectdiscovery/goflags?filename=go.mod)
[![Release](https://img.shields.io/github/release/projectdiscovery/goflags)](https://github.com/projectdiscovery/goflags/releases/)
[![Checks](https://github.com/projectdiscovery/goflags/actions/workflows/build-test.yml/badge.svg)](https://github.com/projectdiscovery/goflags/actions/workflows/build-test.yml)

An extension of the go `flag` library that adds convenience functions and functionalities like config file, better usage, short and long flag support, custom types for string slices and maps etc.

## Features

- YAML configuration with ordered file precedence.
- Better usage instructions
- Short and long flags support
- Custom String Slice types with different options (comma-separated,normalized,etc)
- Custom Map type
- Flags grouping support (CreateGroup,SetGroup)

## Usage

The following types are supported by the goflags library. The `<name>P` suffix means that the flag supports both a long and a short flag for the option.

### Flag Types

| Function                 | Description                                                         |
|--------------------------|---------------------------------------------------------------------|
| BoolVar                  | Boolean value with long name                                        |
| BoolVarP                 | Boolean value with long short name                                  |
| DurationVar              | Time Duration value with long name                                  |
| DurationVarP             | Time Duration value with long short name                            |
| IntVar                   | Integer value with long name                                        |
| IntVarP                  | Integer value with long short name                                  |
| PortVar                  | Port value with long name											 |
| PortVarP                 | Port value with long short name									 |
| RuntimeMapVar            | Map value with long name                                            |
| RuntimeMapVarP           | Map value with long short name                                      |
| StringSliceVar           | String Slice value with long name and options                       |
| StringSliceVarConfigOnly | String Slice value with long name read from config file only        |
| StringSliceVarP          | String slice value with long short name and options                 |
| StringVar                | String value with long name                                         |
| StringVarEnv             | String value with long short name read from environment             |
| StringVarP               | String value with long short name                                   |
| Var                      | Custom value with long name implementing flag.Value interface       |
| VarP                     | Custom value with long short name implementing flag.Value interface |
| EnumVar                  | Enum value with long name                                           |
| EnumVarP                 | Enum value with long short name                                     |
| AuthVar                  | Auth token with long name (supports interactive prompt and env var) |
| AuthVarP                 | Auth token with long short name                                     |
| CallbackVar			   | Callback function as value with long name							 |
| CallbackVarP			   | Callback function as value with long short name					 |
| SizeVar                  | String value with long name                                         |
| SizeVarP                 | String value with long short name                                   |


### String Slice Options

| String Slice Option                  | Tokenization | Normalization | Description                                   |
|--------------------------------------|--------------|---------------|-----------------------------------------------|
| StringSliceOptions                   | None         | None          | Default String Slice                          |
| CommaSeparatedStringSliceOptions     | Comma        | None          | Comma-separated string slice                  |
| FileCommaSeparatedStringSliceOptions | Comma        | None          | Comma-separated items from file/cli           |
| NormalizedOriginalStringSliceOptions | None         | Standard      | List of normalized string slice               |
| FileNormalizedStringSliceOptions     | Comma        | Standard      | List of normalized string slice from file/cli |
| FileStringSliceOptions               | Standard     | Standard      | List of string slice from file                |
| NormalizedStringSliceOptions         | Comma        | Standard      | List of normalized string slice               |

### Cascading Configuration

Use `SetConfigFilePaths` to load more than one YAML configuration file. List the
files from lowest to highest priority. For example, you can load system-wide
configuration first and let the user's configuration override it:

```go
userConfigFile, err := flagSet.GetConfigFilePath()
if err != nil {
	log.Fatal(err)
}

flagSet.SetConfigFilePaths("/etc/example/config.yaml", userConfigFile)
if err := flagSet.Parse(); err != nil {
	log.Fatal(err)
}
```

The following precedence rules apply:

- Command-line flags override all configuration files.
- A value in a later file overrides the value from an earlier file.
- If a later file does not contain an option, the earlier value remains in use.

The last path is the primary user configuration file. `Parse` creates this file
if it does not exist. Missing lower-priority files are skipped, but other file
errors are returned. Earlier files are always read-only.

`Parse` and `MergeConfigFile` return configuration errors (malformed YAML,
unsupported or invalid values). A failure while applying cascaded files rolls
back every assignment from that apply, including values from lower-priority
files, so compiled defaults remain. Sequential `MergeConfigFile` calls roll
back only the failed file.

Built-in collection types replace the complete collection instead of merging
items. Custom `flag.Value` implementations keep their own `Set` behavior.
Callback flags are CLI-only, so configuration files cannot run them.

## Example

An example showing various options of the library is specified below.

```go
package main

import (
	"fmt"
	"log"

	"github.com/projectdiscovery/goflags"
)

type options struct {
	silent bool
	inputs goflags.StringSlice
	config string
	values goflags.RuntimeMap
}

const (
	Nil goflags.EnumVariable = iota
	Type1
	Type2
)

func main() {
	enumAllowedTypes := goflags.AllowdTypes{"type1": Type1, "type2": Type2}
	opt := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Test program to demonstrate goflags options")

	flagSet.EnumVarP(&options.Type, "enum-type", "et", Nil, "Variable Type (type1/type2)", enumAllowedTypes)
	flagSet.BoolVar(&opt.silent, "silent", true, "show silent output")
	flagSet.StringSliceVarP(&opt.inputs, "inputs", "i", nil, "list of inputs (file,comma-separated)", goflags.FileCommaSeparatedStringSliceOptions)

	update := func(tool string ) func() { 
		return func()  {
			fmt.Printf("%v updated successfully!", tool)
		}
	}
	flagSet.CallbackVarP(update("tool_1"), "update", "up", "update tool_1")


	// Group example
	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&opt.config, "config", "", "file to read config from"),
		flagSet.RuntimeMapVar(&opt.values, "values", nil, "key-value runtime values"),
	)
	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s\n", err)
	}
	if opt.config != "" {
		if err := flagSet.MergeConfigFile(opt.config); err != nil {
			log.Fatalf("Could not merge config file: %s\n", err)
		}
	}
	fmt.Printf("silent: %v inputs: %v config: %v values: %v\n", opt.silent, opt.inputs, opt.config, opt.values)
}
```

### Thanks

1. spf13/cobra - For the very nice usage template for the command line.
2. nmap/nmap - For the service-port mapping and top-ports list.
