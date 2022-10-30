package models

import (
	"gorm.io/gorm"
)

// 存储到ES
type SubDomain struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Tags       string   `json:"tags,omitempty"` // 标识属于那个tag，例如hackerone
}

//http://127.0.0.1:9200/domain_index/_search?q=domain:%20in%20*qianxin*
type Domain struct {
	Domain string   `json:"domain"`
	Ips    []string `json:"ips"`
}

/*
局部性更新文档，下面的代码借助go json的omitempty，在将更新数据对象序列化成json，
可以只序列化非零值字段，实现局部更新。 实际项目采用这种方式时，
需要注意某个字段的零值具有业务意义时，可以采用对应的指针类型实现
*/
type SubDomainItem struct {
	gorm.Model
	Domain    string `json:"domain" gorm:"type:varchar(100);"`
	SubDomain string `json:"subDomain" gorm:"type:varchar(100);"`
	ToolName  uint64 `json:"toolName,omitempty" gorm:"type:varchar(100);"` // 支持多个工具
	Tags      string `json:"tags,omitempty" gorm:"type:varchar(200);"`     // 标识属于那个tag，例如hackerone
}

// domain to ips
// ip to Domain
type Domain2Ips struct {
	gorm.Model
	Domain   string `json:"domain" gorm:"type:varchar(100);"`
	Ip       string `json:"ip" gorm:"type:varchar(50);"`
	ToolName uint64 `json:"toolName,omitempty" gorm:"type:varchar(200);"` // 支持多个工具
}

// 端口扫描，及端口漏洞扫描
type Ip2Ports struct {
	gorm.Model
	MyId          string `json:"myId,omitempty" gorm:"type:varchar(100);"` // 对应ES domain id，可以为空
	Ip            string `json:"ip" gorm:"type:varchar(50);"`
	Port          int    `json:"port"`
	Des           string `json:"des,omitempty" gorm:"type:varchar(500);"`
	ToolName      uint64 `json:"toolName,omitempty" gorm:"type:varchar(200);"` // 支持多个工具
	VulsCheckFlag uint64 `json:"vulsCheckFlag,omitempty"`                      // 每一位表示一个工具，所以，可以支持64种工具、插件对该port进行扫描
	VulsCheckRst  string `json:"vulsCheckRst,omitempty" gorm:"type:varchar(1000);"`
}

// ip 经纬度 info
// curl -H 'User-Agent:curl/1.0' http://ip-api.com/json/107.182.191.202|jq
type IpInfo struct {
	gorm.Model
	Continent     string  `json:"continent" gorm:"type:varchar(200);"`
	ContinentCode string  `json:"continentCode" gorm:"type:varchar(200);"`
	Country       string  `json:"country" gorm:"type:varchar(50);"`
	CountryCode   string  `json:"countryCode" gorm:"type:varchar(50);"`
	Region        string  `json:"region" gorm:"type:varchar(50);"`
	RegionName    string  `json:"regionName" gorm:"type:varchar(100);"`
	City          string  `json:"city" gorm:"type:varchar(100);"`
	District      string  `json:"district" gorm:"type:varchar(100);"`
	Zip           string  `json:"zip" gorm:"type:varchar(30);"`
	Lat           float64 `json:"lat"`
	Lon           float64 `json:"lon"`
	Timezone      string  `json:"timezone"  gorm:"type:varchar(30);"`
	Offset        string  `json:"offset"  gorm:"type:varchar(30);"`
	Currency      string  `json:"currency"  gorm:"type:varchar(30);"`
	Isp           string  `json:"isp"  gorm:"type:varchar(30);"`
	Org           string  `json:"org" gorm:"type:varchar(30);"`
	As            string  `json:"as" gorm:"type:varchar(30);"`
	Asname        string  `json:"asname" gorm:"type:varchar(30);"`
	Mobile        string  `json:"mobile" gorm:"type:varchar(30);"`
	Proxy         string  `json:"proxy" gorm:"type:varchar(30);"`
	Hosting       string  `json:"hosting" gorm:"type:varchar(100);"`
	Ip            string  `json:"query" gorm:"type:varchar(50);unique_index"` // IP
}

//// 执行任务
//type Task struct {
//	gorm.Model
//	Target   string `json:"target" gorm:"type:varchar(1000);"`
//	TaskType uint64 `json:"taskType"`
//	PluginId string `json:"pluginId" gorm:"type:varchar(100);"`
//	Status   uint64 `json:"status"` // 状态:待执行，执行中，已完成
//}
