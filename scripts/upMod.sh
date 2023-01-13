go get "$1"
go mod tidy;go mod vendor

git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go

git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go
git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/scan/scan.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/runner/options.go
git checkout vendor/github.com/projectdiscovery/nuclei/v2

git add vendor
/usr/bin/git -c protocol.version=2 submodule update --remote --force --recursive
