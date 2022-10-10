export GOPRIVATE=github.com/hktalent
cat go.mod|grep hktalent|grep -v module|awk '{print $1}'|xargs -I % go get %
go mod tidy
go mod verify
go mod vendor
go vet
git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go
git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go
echo "test build"
git submodule update --init --recursive --remote
go build

#rm -rf vendor/github.com/hktalent/goSqlite_gorm
#ln -s $HOME/MyWork/goSqlite_gorm $PWD/vendor/github.com/hktalent/goSqlite_gorm

git log --oneline --decorate
git log --oneline --decorate 2.8.3
git log --oneline --decorate 2.8.2..2.8.3