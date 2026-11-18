# errkit

why errkit when we already have errorutil ? 

----

Introduced a year ago, `errorutil` aimed to capture error stacks for identifying deeply nested errors. However, its approach deviates from Go's error handling paradigm. In Go, libraries like "errors", "pkg/errors", and "uber.go/multierr" avoid using the `.Error()` method directly. Instead, they wrap errors with helper structs that implement specific interfaces, facilitating error chain traversal and the use of helper functions like `.Cause() error` or `.Unwrap() error` or `errors.Is()`. Contrarily, `errorutil` marshals errors to strings, which is incompatible with Go's error handling paradigm. Over time, the use of `errorutil` has become cumbersome due to its inability to replace any error package seamlessly and its lack of support for idiomatic error propagation or traversal in Go.


`errkit` is a new error library that addresses the shortcomings of `errorutil`. It offers the following features:

- Seamless replacement for existing error packages, requiring no syntax changes or refactoring:
    - `errors` package
    - `pkg/errors` package (now deprecated)
    - `uber/multierr` package
- `errkit` is compatible with all known Go error handling implementations. It can parse errors from any library and works with existing error handling libraries and helper functions like `Is()`, `As()`, `Cause()`, and more.
- `errkit` is Go idiomatic and adheres to the Go error handling paradigm.
- `errkit` supports attributes for structured error information or logging using `slog.Attr` (optional).
- `errkit` implements and categorizes errors into different kinds, as detailed below.
    - `ErrKindNetworkTemporary`
    - `ErrKindNetworkPermanent`
    - `ErrKindDeadline`
    - Custom kinds via `ErrKind` interface
- `errkit` provides helper functions for structured error logging using `SlogAttrs` and `SlogAttrGroup`.
- `errkit` offers helper functions to implement public or user-facing errors by using error kinds interface.


**Attributes Support**

`errkit` supports optional error wrapping with attributes `slog.Attr` for structured error logging, providing a more organized approach to error logging than string wrapping.

```go
// normal way of error propogating through nested stack
err := errkit.New("i/o timeout")

// xyz.go
err := errkit.Wrap(err,"failed to connect %s",addr)

// abc.go
err := errkit.Wrap(err,"error occured when downloading %s",xyz)
```

with attributes support you can do following

```go
// normal way of error propogating through nested stack
err := errkit.New("i/o timeout")

// xyz.go
err = errkit.WithAttr(err, slog.String("resource", domain))

// abc.go
err = errkit.WithAttr(err, slog.String("action", "download"))
```

## Note

To keep errors concise and avoid unnecessary allocations, message wrapping and attributes count have a max depth set to 3. Adding more will not panic but will be simply ignored. This is configurable using the MAX_ERR_DEPTH env variable (default 3).