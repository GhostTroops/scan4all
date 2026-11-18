# gologger slog Compatibility Guide

`*gologger.Logger` implements `slog.Handler`. You can drop it into `slog.New(...)` to get gologger's CLI output through the standard `log/slog` API, without changing any existing gologger calls.

## Table of Contents

- [Quick Start](#quick-start)
- [Levels](#levels)
- [Attribute Types](#attribute-types)
- [Groups and Persistent Attributes](#groups-and-persistent-attributes)
- [Migration](#migration)
- [Clean Level Names for JSON/Text Handlers](#clean-level-names-for-jsontext-handlers)

## Quick Start

```go
package main

import (
    "log/slog"

    "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/gologger/levels"
)

func main() {
    gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
    slog.SetDefault(slog.New(gologger.DefaultLogger))

    gologger.Info().Msg("Hello from gologger")
    slog.Info("Hello from slog")
    // [INF] Hello from gologger
    // [INF] Hello from slog
}
```

Both APIs share the same writer, formatter, max level, and timestamp settings, and produce identical output.

## Levels

gologger's level hierarchy is exposed as `slog.Level` constants for use with `slog.Log(ctx, level, ...)`:

| Constant                | slog offset | gologger level | Label |
| ----------------------- | ----------- | -------------- | ----- |
| `gologger.LevelTrace`   | DEBUG − 4   | Verbose        | `VER` |
| `gologger.LevelVerbose` | DEBUG − 2   | Verbose        | `VER` |
| `slog.LevelDebug`       | -4          | Debug          | `DBG` |
| `slog.LevelInfo`        | 0           | Info           | `INF` |
| `gologger.LevelSilent`  | INFO + 1    | Silent         | *(none)* |
| `slog.LevelWarn`        | 4           | Warning        | `WRN` |
| `slog.LevelError`       | 8           | Error          | `ERR` |
| `gologger.LevelFatal`   | ERROR + 4   | Fatal          | `FTL` (then `os.Exit(1)`) |

```go
slog.Log(ctx, gologger.LevelVerbose, "detailed step")
slog.Log(ctx, gologger.LevelSilent, "no label, just text")
```

## Attribute Types

All standard `slog` attribute kinds are converted to gologger metadata strings:

| `slog.Kind` | Conversion                                |
| ----------- | ----------------------------------------- |
| String      | as-is                                     |
| Int / Uint  | decimal                                   |
| Float       | `%g`; `NaN`, `+Inf`, `-Inf` for specials  |
| Bool        | `"true"` / `"false"`                      |
| Duration    | `time.Duration.String()`                  |
| Time        | RFC3339 (or `0001-01-01T00:00:00Z` if zero) |
| Any         | `fmt.Sprintf("%+v", ...)`                 |
| Group       | flattened into dotted keys (see below)    |

```go
slog.Info("user activity",
    slog.String("name", "john"),
    slog.Int("age", 30),
    slog.Bool("active", true),
    slog.Float64("score", 95.5),
    slog.Duration("latency", 100*time.Millisecond),
    slog.Time("login", time.Now()),
    slog.Any("custom", map[string]int{"visits": 42}),
)
// [INF] user activity [name=john,age=30,active=true,score=95.5,latency=100ms,login=2023-12-07T10:30:00Z,custom=map[visits:42]]
```

## Groups and Persistent Attributes

`WithGroup` flattens nested groups into dotted keys. `WithGroup("")` returns the receiver unchanged, per the `slog.Handler` contract.

```go
logger := slog.New(gologger.DefaultLogger).
    WithGroup("api").
    WithGroup("request")

logger.Info("processing", slog.String("method", "POST"), slog.String("path", "/users"))
// [INF] processing [api.request.method=POST,api.request.path=/users]
```

`WithAttrs` persists attributes across subsequent log calls:

```go
svc := slog.New(gologger.DefaultLogger).With(
    slog.String("service", "user-api"),
    slog.String("version", "1.0.0"),
)
svc.Info("request processed", slog.String("endpoint", "/login"))
// [INF] request processed [service=user-api,version=1.0.0,endpoint=/login]
```

## Migration

Setup once:

```go
func init() {
    gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
    slog.SetDefault(slog.New(gologger.DefaultLogger))
}
```

After that, existing `gologger.*` calls keep working and any new `slog.*` calls produce the same output. There is no required big-bang migration — both APIs can coexist in the same binary:

```go
gologger.Info().Str("component", "legacy").Msg("legacy path")
slog.Info("new path", slog.String("component", "new"))
```

`slog.InfoContext`, cancellation, and other context-aware variants are supported; `Handle` returns `ctx.Err()` if the context is already cancelled.

## Clean Level Names for JSON/Text Handlers

When you want to pipe the *custom* gologger levels through a standard slog handler (JSON / Text) and avoid raw labels like `DEBUG-4` or `ERROR+4`, use `TrimGologgerLevels()`:

```go
handler := slog.NewJSONHandler(os.Stdout, gologger.TrimGologgerLevels())
logger := slog.New(handler)

logger.Log(ctx, gologger.LevelTrace,  "trace message")
logger.Log(ctx, gologger.LevelFatal,  "fatal message")
logger.Log(ctx, gologger.LevelSilent, "silent message")
```

```json
{"time":"...", "level":"TRACE", "msg":"trace message"}
{"time":"...", "level":"FATAL", "msg":"fatal message"}
{"time":"...",                  "msg":"silent message"}
```

The Silent level emits no `level` field, by design.
