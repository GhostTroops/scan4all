# freeport

Extended and revisited version of `https://github.com/phayes/freeport` - Get a free port from the OS.


```go
...

tcpPort, err := freeport.GetFreePort("127.0.0.1", freeport.TCP)
if err != nil {
    panic(err)
}
fmt.Println("TCP port: ", tcpPort.Port)

fmt.Println("Multiple ports:")

// get multiple ports
// test with TCP
tcpPorts, err := freeport.GetFreePorts("127.0.0.1", freeport.TCP, 5)
if err != nil {
    panic(err)
}

for _, port := range tcpPorts {
    fmt.Println("TCP port: ", port.Port)
}

...
```

output:
```
Single port:
UDP port:  57224
TCP port:  51655
Multiple ports:
TCP port:  51656
TCP port:  51657
TCP port:  51658
TCP port:  51659
TCP port:  51660
```

# License

freeport is distributed under MIT License