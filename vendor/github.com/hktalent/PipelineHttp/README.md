# PipelineHttp

# What features
- auto support HTTP/2.0
- support HTTP/3.0

# How install cmd
```
go get -u ./...
go build -o ppHttp cmd/main.go
ln -s $PWD/ppHttp $HOME/go/bin/ppHttp
# go install github.com/hktalent/PipelineHttp/cmd/@latest
```
# How use
```
ppHttp https://xx1.com https://b1.xx2.com
```

# Test speed
- http 2.0 18s req 30612 * 2(host) times
