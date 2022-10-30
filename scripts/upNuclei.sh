cd $HOME/MyWork/nuclei-templates
git pull
cd $HOME/MyWork/scan4all/
ls ../nuclei-templates|xargs -I % cp -rf ../nuclei-templates/% config/nuclei-templates/
git add config/nuclei-templates pocs_yml/ymlFiles vendor
git checkout vendor/github.com/projectdiscovery/nuclei/v2
git status
find . -name ".DS_Store" -delete
rm -rf logs/*
rm -rf .DbCache
