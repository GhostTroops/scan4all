# ipranger

ipranger helps you to keep track of yours ip with the integration of [ProjectDiscovery hmap](https://github.com/projectdiscovery/hmap) key value store.

ipranger also integrate [mapcidr](https://github.com/projectdiscovery/mapcidr) library:

```go
...
ips, err := ipranger.Ips("127.0.0.1/16")
if err != nil {
	panic(err)
}
fmt.Println(len(ips))
...
```

# License
ipranger is distributed under MIT License