# jarm-go

This is a Go implementation of [JARM](https://github.com/salesforce/jarm).

# jarmscan

To install jarmscan, download a binary from the [releases](https://github.com/RumbleDiscovery/jarm-go/releases) page or install using `go get -u -v github.com/RumbleDiscovery/jarm-go/cmd/jarmscan`.

To run a scan, provide a list of targets. The following examples are all supported:

* `jarmscan www.rumble.run`
* `jarmscan -p 443,8443 192.168.0.1`
* `jarmscan -p 1-1024 https://www.example.com/`
* `jarmscan -p 443,465,993,995,8443,9443 192.168.0.0/24`
* `jarmscan 192.168.0.1:8443`
* `jarmscan 192.168.0.1,443`

The `-q` option can be used to disable verbose output and the `-w` parameter can be used to increase the worker count.

The `-p` option allows port lists and port ranges to be specified in a form similar to Nmap.

# jarm

To use the jarm-go library from a Go application please review the `Fingerprint()` function in the `cmd/jarmscan/main.go` code.

The basic process involves:

* Creating a list of probes for a given host and port using `GetProbes()`. The host is sent as part of the client probe.
* Building each individual probe in the order they are returned using `BuildProbe()`.
* Opening a connection to the host and port and sending the probe. 
* Receiving the response (up to 1484 bytes). Receiving more or less can change the hash.
* Parsing the Server Hello from the received data using `ParseServerHello()`.
* Calculating the JARM hash using `RawHashToFuzzyHash()`.