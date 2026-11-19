go get "$1"
go mod tidy;go mod vendor

git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/scan/scan.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/runner/options.go

git add vendor
/usr/bin/git -c protocol.version=2 submodule update --remote --force --recursive
