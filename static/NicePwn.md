# 最佳实践
本文以mac os系统为例

## 结果持久化保存
* 1、请自行先安装好docker（安装过程略）
* 2、mkdir ~/MyWork;cd ~/MyWork;git clone http://github.com/hktalent/scan4all
* 3、cd ~/MyWork/scan4all
* 4、运行下面的代码，自动获取docker，并启动docker服务，端口9200
```bash
docker run --restart=always --ulimit nofile=65536:65536 -p 9200:9200 -p 9300:9300 -d --name es -v $PWD/logs:/usr/share/elasticsearch/logs -v $PWD/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options  -v $PWD/data:/usr/share/elasticsearch/data  hktalent/elasticsearch:7.16.2
```
* 5、运行 初始化索引库
```
~/MyWork/scan4all/config/initEs.sh
```
## 启动结果存储到ES
修改 config/config.json 中为true开启存储结果
```
"enableEsSv": true,
```
如果你的ES设置了密码，请修改
config/nuclei_esConfig.yaml
中的密码，否则里面的密码设置都无意义

## 运行扫描任务
./