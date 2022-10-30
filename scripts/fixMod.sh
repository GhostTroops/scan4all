go get "github.com/projectdiscovery/goflags@v0.0.8-0.20220610073650-5d31a8c159e3"
go get github.com/projectdiscovery/retryabledns@v1.0.13
go get "github.com/cockroachdb/pebble@v0.0.0-20210728210723-48179f1d4dae"
go get "github.com/projectdiscovery/stringsutil@v0.0.0-20220612082425-0037ce9f89f3"
go get "github.com/projectdiscovery/ipranger@v0.0.3-0.20210831161617-ac80efae0961"
go get "github.com/go-rod/rod/lib/proto"

go get "github.com/projectdiscovery/nuclei/v2@v2.7.8"

go mod tidy;go mod vendor

git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go
git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/scan/scan.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/runner/options.go
git checkout vendor/github.com/projectdiscovery/nuclei/v2

go build

git add vendor
rm -rf vendor/github.com/hktalent/51pwnPlatform
ln -s $HOME/MyWork/goSqlite_gorm $PWD/vendor/github.com/hktalent/51pwnPlatform

go mod tidy;go mod vendor;
go mod vendor;go vet

# login 优先
cat brute/dicts/filedic.txt|grep "\/[lL]ogin">x1.txt
cat brute/dicts/filedic.txt|grep -v "\/[lL]ogin">x2.txt
sort x1.txt >x11.txt
sort x2.txt >x22.txt
cat x11.txt x22.txt >brute/dicts/filedic.txt
rm -rf x11.txt x22.txt x1.txt x2.txt