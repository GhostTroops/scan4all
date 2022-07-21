cd $HOME/MyWork/nuclei-templates
git pull
cd $HOME/MyWork/scan4all
cat ./go.mod|grep projectdiscovery|grep -E "subfinder|nuclei|wappalyzergo"|awk '{print $1}'|xargs -I % go get -u %

ls ../nuclei-templates|xargs -I % cp -rf ../nuclei-templates/% config/nuclei-templates/
go mod tidy
go mod vendor
# 工具静态分析代码实现
go vet

cat ./pkg/fingerprint/dicts/eHoleFinger.json|jq ".fingerprint[].cms"|wc -l
cat ./pkg/fingerprint/dicts/localFinger.json|jq ".fingerprint[].cms"|wc -l
cat ./pkg/fingerprint/dicts/fg.json|jq ".[].kind"|wc -l
git add config/nuclei-templates
git status
go build


