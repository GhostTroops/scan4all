# leakless

Run sub-process and make sure to kill it when the parent process exits.
The way how it works is to output a standalone executable file to guard the subprocess and check parent TCP connection with a UUID.
So that it works consistently on Linux, Mac, and Windows.

If you don't trust the executable, you can build it yourself from the source code by running `go generate` at the root of this repo, then use the [replace](https://golang.org/ref/mod#go-mod-file-replace) to use your own module. Usually, it won't be a concern, all the executables are committed by this [Github Action](https://github.com/ysmood/leakless/actions?query=workflow%3ARelease), the Action will print the hash of the commit, you can compare it with the repo.

Not using the PID is because after a process exits, a newly created process may have the same PID.

## How to Use

See the [examples](example_test.go).

## Custom build for `GOOS` or `GOARCH`

Such as if you want to support FreeBSD, you can clone this project and modify the [targets.go](cmd/pack/targets.go) to something like:

```go
var targets = []utils.Target{
    "freebsd/amd64",
}
```

Then run `go generate` and use [replace](https://golang.org/ref/mod#go-mod-file-replace) in the project that will use leakless.
You can keep this fork of leakless to serve your own interest.
