# 编译

```sh
sudo apt install -y libpcap-dev golang git
git clone https://github.com/hktalent/scan4all.git
cd scan4all
go build
```

# 安装/运行

1.在运行scan4all之前，你必须先安装libpcap库

```sh
# ubuntu、linux
apt update
apt install -yy libpcap0.8-dev
sudo apt install -y libpcap-dev
# cent os
yum install -yy glibc-devel.x86_64
yum install -yy libpcap
# mac os
brew install libpcap

```

2.前往
[https://github.com/hktalent/scan4all/releases/](https://github.com/hktalent/scan4all/releases/)
下载scan4all最新版运行:

## 运行时动态库版本问题

如果你运行的时候出现了`libpcap.so.0.8: cannot open shared object file: No such file or directory`的错误

请先检查libpcap库是否已经正常安装。
```sh
ls -all /lib64/libpcap*
```
如果有安装其他版本的libpcap库，可建立一个软连接到/lib64/libpcap.so.0.8即可正常运行程序

```sh
ln -s /lib64/libpcap.so.1.9.1 /lib64/libpcap.so.0.8
```

## docker ubuntu
```bash 
apt update;apt install -yy libpcap0.8-dev
```
## centos
```bash
yum install -yy glibc-devel.x86_64
```
### linux
too many open files
查看当前打开的文件数
```
awk '{print $1}' /proc/sys/fs/file-nr
ulimit -a
ulimit -n 819200
```