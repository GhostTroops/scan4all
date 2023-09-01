# 最佳实践
本文以mac os系统为例

## 结果持久化保存
* 1、请自行先安装好docker（安装过程略）
* 2、mkdir ~/MyWork;cd ~/MyWork
  * 2.1 config目录及相关配置文件
  下载release程序运行，首次运行非自动生成config目录及相关配置文件，或者：  
  git clone http://github.com/hktalent/scan4all
  
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

### 配置说明
完整版本，查看:config/config.json
```json
{
  "CacheName": ".DbCache", // 提速、优化、避免重复，缓存目录
  "autoRmCache": "true",   // 程序自动删除缓存，如果你希望保留下次相同目标提速，可以保留
  //////////各种不需要我说对可自定义字典，你可以配置相同文件 start///////////////
  "ssh_username": "pkg/hydra/dicts/ssh_user.txt",
  "ssh_pswd": "pkg/hydra/dicts/ssh_pswd.txt",
  "ssh_default": "pkg/hydra/dicts/ssh_default.txt",
  "ftpusername": "pkg/hydra/dicts/ftp_user.txt",
  "ftp_pswd": "pkg/hydra/dicts/ftp_pswd.txt",
  "ftp_default": "pkg/hydra/dicts/ftp_default.txt",
  "rdpusername": "pkg/hydra/dicts/rdp_user.txt",
  "rdp_pswd": "pkg/hydra/dicts/rdp_pswd.txt",
  "rdp_default": "pkg/hydra/dicts/rdp_default.txt",
  "mongodbusername": "pkg/hydra/dicts/mongodb_user.txt",
  "mongodb_pswd": "pkg/hydra/dicts/mongodb_pswd.txt",
  "mongodb_default": "pkg/hydra/dicts/mongodb_default.txt",
  "mssqlusername": "pkg/hydra/dicts/mssql_user.txt",
  "mssql_pswd": "pkg/hydra/dicts/mssql_pswd.txt",
  "mssql_default": "pkg/hydra/dicts/mssql_default.txt",
  "mysqlusername": "pkg/hydra/dicts/mysql_user.txt",
  "mysql_pswd": "pkg/hydra/dicts/mysql_pswd.txt",
  "mysql_default": "pkg/hydra/dicts/mysql_default.txt",
  "oracleusername": "pkg/hydra/dicts/oracle_user.txt",
  "oracle_pswd": "pkg/hydra/dicts/oracle_pswd.txt",
  "oracle_default": "pkg/hydra/dicts/oracle_default.txt",
  "postgresqlusername": "pkg/hydra/dicts/postgresql_user.txt",
  "postgresql_pswd": "pkg/hydra/dicts/postgresql_pswd.txt",
  "postgresql_default": "pkg/hydra/dicts/postgresql_default.txt",
  "redisusername": "pkg/hydra/dicts/redis_user.txt",
  "redis_pswd": "pkg/hydra/dicts/redis_pswd.txt",
  "redis_default": "pkg/hydra/dicts/redis_default.txt",
  "smbusername": "pkg/hydra/dicts/smb_user.txt",
  "smb_pswd": "pkg/hydra/dicts/smb_pswd.txt",
  "smb_default": "pkg/hydra/dicts/smb_default.txt",
  "telnetusername": "pkg/hydra/dicts/telnet_user.txt",
  "telnet_pswd": "pkg/hydra/dicts/telnet_pswd.txt",
  "telnet_default": "pkg/hydra/dicts/telnet_default.txt",
  "tomcatuserpass": "brute/dicts/tomcatuserpass.txt",
  "jbossuserpass": "brute/dicts/jbossuserpass.txt",
  "weblogicuserpass": "brute/dicts/weblogicuserpass.txt",
  "filedic": "brute/dicts/filedic.txt",
  "top100pass": "brute/dicts/top100pass.txt",
  "bakSuffix": "brute/dicts/bakSuffix.txt",
  "fuzzct": "brute/dicts/fuzzContentType1.txt",
  "fuzz404": "brute/dicts/fuzz404.txt",
  "page404Content1": "brute/dicts/page404Content.txt",
  "eHoleFinger": "pkg/fingerprint/dicts/eHoleFinger.json",
  "localFinger": "pkg/fingerprint/dicts/localFinger.json",
  "HydraUser": "",
  "HydraPass": "",
  "es_user": "pkg/hydra/dicts/es_user.txt",
  "es_pswd": "pkg/hydra/dicts/es_pswd.txt",
  "es_default": "pkg/hydra/dicts/es_default.txt",
  "snmp_user": "pkg/hydra/dicts/snmp_user.txt",
  "snmp_pswd": "pkg/hydra/dicts/snmp_pswd.txt",
  "snmp_default": "pkg/hydra/dicts/snmp_default.txt",
  //////////各种不需要我说对可自定义字典，你可以配置相同文件 end///////////////
  // naabu 扫描到到端口后自动调用nmap跑指纹，然后自动调用弱口令检测，windows自动加.exe你不需要关注
  "nmap": "nmap -n --unique --resolve-all -Pn --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m -oX {filename} --version-intensity 9 --min-rate 10000 -T4 ",
  "UrlPrecise": true, // -l 传入文件清单如果是http[s]带上下文，默认启动精准扫描
  "ParseSSl": false,  // HW打点默认关闭，互联网赏金目标建议设置true
  "EnableSubfinder": false, // 默认关闭ssl中证书子域名爆破,互联网赏金目标建议设置true
  "naabu_dns": {},  // naabu工具对dns配置
  "naabu": {"TopPorts": "1000","ScanAllIPS": true}, // naabu配置
  "nuclei": {}, // nuclei配置，例如线程等
  "httpx": {}   // httpx 配置,
  "enableEsSv": true,        // 开启结果send 到es
  "esthread": 8 // 结果写入Elasticsearch的线程数,
  "esUrl": "http://127.0.0.1:9200/%s_index/_doc/%s" // Elasticsearch szUrl
}
```

## 运行扫描任务
一般不批量的时候，除非想看中间结果，不建议开启 -v -debug
```bash
enableEsSv=true ./scan4all -l list.txt
enableEsSv=true ./scan4all -host target.com
```

## 查看结果
更多索引类型见
config/initEs.sh
```
http://127.0.0.1:9200/nmap_index/_doc/156.238.15.99
http://127.0.0.1:9200/nuclei_index/_doc/_search?q=host:%20in%20%221.2.215.18:1432%22
http://127.0.0.1:9200/naabu_index/_doc/_search
http://127.0.0.1:9200/vscan_index/_doc/_search
http://127.0.0.1:9200/hydra_index/_doc/_search
http://127.0.0.1:9200/httpx_index/_doc/_search
http://127.0.0.1:9200/httpx_index/_doc/_search?q=szUrl:in%20%221.28.15.18%22

```