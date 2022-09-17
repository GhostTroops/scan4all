rm -rf vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go
rm -rf vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go
wget -c -O vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go https://github.com/hktalent/scan4all/raw/main/vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go
wget -c -O vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go https://github.com/hktalent/scan4all/raw/main/vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go
go build

find . -name ".DS_Store" -delete
