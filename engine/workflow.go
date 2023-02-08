package engine

/*
深度处理器，每次的结果迭代到其他项目
每个项目处理前判断是否已经处理
每个项目初始化加载数据，交接到下一流程

# Recon, OSINT & Discovery
https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/tools.md
https://github.com/tomnomnom/httprobe
https://github.com/j3ssie/Osmedeus

1、ip to domain
2、domain to ip
3、subdomain ,比较消耗网路资源，单线程进行
echo $PPSSWWDD| sudo -S ksubdomain enum -b 5M -d huazhu.com -f $HOME/MyWork/scan4all/config/database/subdomain.txt -o json/huazhu.json
echo $PPSSWWDD| sudo -S ./ksubdomain enum -b 5M -d qq.com -f $HOME/MyWork/scan4all/config/database/subdomain.txt -o qq.com.json
cat $HOME/MyWork/bounty-targets-data/data/hackerone_data.json|jq ".[].targets.in_scope[0].asset_identifier"|grep '"\*\.'|sed 's/"//g'|sed 's/^\*\.//g' >lists.txt
echo $PPSSWWDD| sudo -S ./ksubdomain enum -b 5M --dl lists.txt -f $HOME/MyWork/scan4all/config/database/subdomain.txt

4、tlsx
5、http header
6、httpx
7、ffuf
7、nuclei，https走domain
8、go-poc

*/
