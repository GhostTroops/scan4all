package portScan

import (
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"strings"
)

/*
在Windows上或从虚拟机上，它可以每秒执行30万个数据包。
在Linux上（没有虚拟化），它将每秒执行160万个数据包。这足以融化大多数网络。

默认情况下，masscan首先加载配置文件 /etc/masscan/masscan.conf
任何后续配置参数都会覆盖此默认配置文件中的内容

二进制：这是mascan内置格式。它产生的文件要小得多，所以当我扫描互联网时，我的磁盘不会填满。
不过，它们需要解析。命令行选项--readscan将读取二进制扫描文件。将--readscan与-oX选项一起使用将生成结果文件的XML版本。
masscan -c myscan.conf

# My Scan
rate =  100000.00
output-format = xml
output-status = all
output-filename = scan.xml
Ports = 0-65535
range = 0.0.0.0-255.255.255.255
excludefile = exclude.txt
*/
func init() {
	util.RegInitFunc(func() {
		// 每个端口大约10小时内扫描整个互联网（减去排除值）（如果扫描所有端口，则扫描655,360小时）
		// 与nmap兼容的“隐形”选项：-sS -Pn -n --randomize-hosts --send-eth
		util.EngineFuncFactory(Const.ScanType_Masscan, func(evt *models.EventData, args ...interface{}) {
			ip := strings.Join(evt.Target2Ip(), ",")
			if "" == ip {
				return
			}
			//s1 := fmt.Sprintf("%x", ip)
			ms := New()
			ms.Evt = evt
			ms.Target = TargetStr(ip)
			ms.Rate = "5000"
			ms.Ports = "0-65535" // -p-  , "-p-"
			ms.Args = []string{
				//"--banners",
				//"-oX", s1 + ".xml",
				"--max-rate", string(ms.Rate),
			}
			util.MergeParms2Obj(&ms, args...)
			var hosts []models.Host
			err := ms.Run(func(host *models.Host) {
				hosts = append(hosts, *host)
			})
			if nil != err {
				log.Println("ms.Run is error ", err)
			}
			util.SendEngineLog(evt, Const.ScanType_Masscan, hosts)
		})

	})
}
