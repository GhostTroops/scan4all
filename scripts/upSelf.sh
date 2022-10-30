export GOPRIVATE=github.com/hktalent
cat go.mod|grep hktalent|grep -v module|awk '{print $1}'|xargs -I % go get %
go mod tidy
go mod verify
go mod vendor
go vet
git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/request.go
git checkout vendor/github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh/interactsh.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/scan/scan.go
git checkout vendor/github.com/projectdiscovery/naabu/v2/pkg/runner/options.go
echo "test build"

git submodule add --force  https://github.com/hktalent/nuclei-templates.git config/nuclei-templates
git submodule add --force  https://github.com/hktalent/jaeles-signatures.git config/jaeles-signatures
git submodule update --init --recursive

# 查找大文件
find . -type f -size +20M

git submodule update --init --recursive --remote
go build

#rm -rf vendor/github.com/hktalent/51pwnPlatform
#ln -s $HOME/MyWork/goSqlite_gorm $PWD/vendor/github.com/hktalent/51pwnPlatform

git log --oneline --decorate
git log --oneline --decorate 2.8.3
git log --oneline --decorate 2.8.2..2.8.3

brew create https://github.com/hktalent/scan4all/releases/download/2.8.5/scan4all_2.8.5_macOS_amd64.zip
