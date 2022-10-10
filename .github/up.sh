upGit xray
upGit nuclei-templates
upGit h2csmuggler
upGit http-request-smuggler
upGit request_smuggler
upGit smuggler

# cd $HOME/MyWork/nuclei-templates
# git fetch  origin master
# git checkout 51pwn
# git merge origin/master


cd $HOME/MyWork/scan4all
cat ./go.mod|grep projectdiscovery|grep -E "subfinder|nuclei|wappalyzergo"|awk '{print $1}'|xargs -I % go get -u %

cp -rf $HOME/MyWork/xray/pocs/*.yml $HOME/MyWork/scan4all/pocs_yml/ymlFiles/
ls ../nuclei-templates|xargs -I % cp -rf ../nuclei-templates/% config/nuclei-templates/
echo "start 静态go.mod去除不相关依赖"
go mod tidy
echo "更新 vendor "
go mod vendor
echo "工具静态分析代码实现"
go vet
#cat ./pkg/fingerprint/dicts/eHoleFinger.json|jq ".fingerprint[].cms"|wc -l
#cat ./pkg/fingerprint/dicts/localFinger.json|jq ".fingerprint[].cms"|wc -l
#cat ./pkg/fingerprint/dicts/fg.json|jq ".[].kind"|wc -l
git add config/nuclei-templates pocs_yml/ymlFiles vendor
git add vendor
git status
go build

wget -c https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-dict.json
wget -c https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-unique-versions-dict.json
wget -c https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-cves-dict.json
mv ms-exchange-versions-dict.json $HOME/MyWork/scan4all/pkg/fingerprint/dicts/
mv ms-exchange-unique-versions-dict.json $HOME/MyWork/scan4all/pkg/fingerprint/dicts/
mv ms-exchange-versions-cves-dict.json $HOME/MyWork/scan4all/pkg/fingerprint/dicts/
