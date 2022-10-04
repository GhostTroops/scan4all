package engine

import (
	"github.com/hktalent/goSqlite_gorm/lib"
	"github.com/hktalent/goSqlite_gorm/lib/scan/Const"
	"github.com/hktalent/goSqlite_gorm/pkg/models"
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pkg/portScan"
)

var (
	CaseScanFunc = map[int]util.EngineFuncType{
		Const.ScanType_SSLInfo:         nil,                     // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
		Const.ScanType_SubDomain:       nil,                     // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
		Const.ScanType_MergeIps:        nil,                     // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
		Const.ScanType_Pswd4hydra:      nil,                     // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
		Const.ScanType_Masscan:         portScan.MassScanTarget, // 05- 合并后的ip 进行快速端口扫描
		Const.ScanType_Nmap:            portScan.DoNmap,         // 06、精准 端口指纹，排除masscan已经识别的几种指纹
		Const.ScanType_IpInfo:          nil,                     // 07- 获取ip info
		Const.ScanType_GoPoc:           nil,                     // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
		Const.ScanType_PortsWeb:        nil,                     // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
		Const.ScanType_WebFingerprints: nil,                     // 10- web指纹，识别蜜罐，并标识
		Const.ScanType_WebDetectWaf:    nil,                     // 11- detect WAF
		Const.ScanType_WebScrapy:       nil,                     // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
		Const.ScanType_WebInfo:         nil,                     // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
		Const.ScanType_WebVulsScan:     nil,                     // 14-nuclei
		Const.ScanType_WebDirScan:      nil,                     // 14-dir爆破,Gobuster
	}
)

// 扫描任务分发
//   为不同类型扫描构造参数，进行事件分发
func Dispather(task *models.Target4Chan) {
	for k, _ := range CaseScanFunc {
		if lib.HasScanType(task.ScanType, k) {
			x1 := &models.EventData{EventType: k, Task: task}
			switch k {
			case Const.ScanType_SSLInfo: // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
				G_Engine.EventData <- x1
			case Const.ScanType_SubDomain: // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
				G_Engine.EventData <- x1
			case Const.ScanType_MergeIps: // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
				G_Engine.EventData <- x1
			case Const.ScanType_Pswd4hydra: // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
				G_Engine.EventData <- x1
			case Const.ScanType_Masscan: // 05- 合并后的ip 进行快速端口扫描; // 06、精准 端口指纹，排除masscan已经识别的几种指纹
				x1.EventData = []interface{}{[]interface{}{portScan.TargetStr(task.ScanWeb)}}
				G_Engine.EventData <- x1
			case Const.ScanType_Nmap: // 05- 合并后的ip 进行快速端口扫描; // 06、精准 端口指纹，排除masscan已经识别的几种指纹
				x1.EventData = []interface{}{x1.Target2Ip(), []string{"0-65535"}}
				G_Engine.EventData <- x1
			case Const.ScanType_IpInfo: // 07- 获取ip info
				G_Engine.EventData <- x1
			case Const.ScanType_GoPoc: // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
				G_Engine.EventData <- x1
			case Const.ScanType_PortsWeb: // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
				G_Engine.EventData <- x1
			case Const.ScanType_WebFingerprints: // 10- web指纹，识别蜜罐，并标识
				G_Engine.EventData <- x1
			case Const.ScanType_WebDetectWaf: // 11- detect WAF
				G_Engine.EventData <- x1
			case Const.ScanType_WebScrapy: // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
				G_Engine.EventData <- x1
			case Const.ScanType_WebInfo: // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
				G_Engine.EventData <- x1
			case Const.ScanType_WebVulsScan: // 14-nuclei
				G_Engine.EventData <- x1
			case Const.ScanType_WebDirScan: // 14-dir爆破,Gobuster
				G_Engine.EventData <- x1
			default:

			}
		}
	}
}
