cat ./go.mod|grep projectdiscovery|grep -E "subfinder|nuclei"|awk '{print $1}'|xargs -I % go get -u %

