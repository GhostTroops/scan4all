# ipisp
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/ammario/ipisp/v2)

ipisp provides a Go client for [Team Cymru's](http://www.team-cymru.org/IP-ASN-mapping.html) IP-ASN mapping service.
Basically, this library allows you to query an IP address' ISP and allocation information.

```
go get github.com/ammario/ipisp/v2
```

## Features
- 0 external dependencies
- Bulk and single lookups

## Basic usage
Running

```go
resp, err := ipisp.LookupIP(context.Background(), net.ParseIP("4.2.2.2"))
if err != nil {
    log.Fatalf("lookup: %v", err)
}
fmt.Printf("ISP: %s\n", resp.ISPName)
```
displays
```
ISP: CTNOSC-ASN-666, US
```