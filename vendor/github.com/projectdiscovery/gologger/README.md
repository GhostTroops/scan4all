# gologger

gologger is a very simple logging package to do structured logging in go. 

## Features

- **Simple and fast structured logging** with beautiful CLI output
- **Fully compatible with Go's standard `log/slog`** package 
- **Zero-breaking-change migration** - use both APIs simultaneously
- **Identical output format** - slog calls produce same CLI appearance
- **Rich metadata support** - structured key-value logging
- **Multiple levels** - Info, Debug, Warning, Error, Fatal, Verbose, Silent
- **Custom formatters** - CLI, JSON, and custom formats
- **Flexible writers** - stdout/stderr, files, rotation, custom writers

## Use gologger as a library

```go
package main

import (
	"strconv"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	//	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})
	gologger.Print().Msgf("\tgologger: sample test\t\n")
	gologger.Info().Str("user", "pdteam").Msg("running simulation program")
	for i := 0; i < 10; i++ {
		gologger.Info().Str("count", strconv.Itoa(i)).Msg("running simulation step...")
	}
	gologger.Debug().Str("state", "running").Msg("planner running")
	gologger.Warning().Str("state", "errored").Str("status", "404").Msg("could not run")
	gologger.Fatal().Msg("bye bye")
}
```

## slog Compatibility

gologger is **fully compatible** with Go's standard `log/slog` package. You can use gologger as an slog handler to get the same beautiful CLI output while leveraging the standard Go logging ecosystem.

### Quick Start with slog

```go
package main

import (
	"log/slog"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	// Setup gologger as slog handler (one-time setup)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	slog.SetDefault(slog.New(gologger.DefaultLogger))
	
	// Now both APIs produce identical output:
	gologger.Info().Str("user", "john").Msg("Hello from gologger") 
	slog.Info("Hello from slog", slog.String("user", "john"))
	
	// Both output: [INF] Hello from gologger [user=john]
	//              [INF] Hello from slog [user=john]
}
```

### Migration Benefits

- **🔄 Zero Breaking Changes**: All existing gologger code continues working
- **🎯 Identical Output**: slog produces the exact same CLI format  
- **📈 Incremental Migration**: Migrate function by function at your own pace
- **🌟 Best of Both Worlds**: Keep gologger's aesthetics, gain slog's ecosystem
- **🔧 Advanced Features**: Groups, persistent attributes, different handler types

### Learn More

See the complete [**slog Compatibility Guide**](./SLOG_COMPATIBILITY.md) for:
- Detailed side-by-side API comparisons with output examples
- How attributes, groups, and custom levels work
- Step-by-step migration strategies  
- Advanced features and best practices

---

gologger is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.