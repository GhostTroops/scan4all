package models

import (
	util "github.com/hktalent/go-utils"
	"gorm.io/gorm"
)

// 任务数据
type Task struct {
	gorm.Model
	Target4Chan `json:",inline"`
	IpInfo      []*ScanIpInfo `json:"mass_scan_ips" gorm:"foreignkey:ID;references:ID"`
	Domains     []*Domains    `json:"domains" gorm:"foreignkey:ID;references:ID"`
	ScanStatus  int           `json:"scan_status"` //  状态，每个位表示响应类型的扫描是否完成，0 表示没有做，1表示做了
}

// 域名信息
type Domains struct {
	gorm.Model
	Dns        string        `json:"dns" gorm:"type:varchar(100)"`
	IpInfo     []*ScanIpInfo `json:"mass_scan_ips" gorm:"many2many:Domains_IpInfo"`
	ScanStatus int           `json:"scan_status"` //  状态，每个位表示响应类型的扫描是否完成，0 表示没有做，1表示做了
}

// 扫描任务的 IP 列表
type ScanIpInfo struct {
	gorm.Model
	Ip         string      `json:"ip" gorm:"unique_index;type:varchar(60)"`
	ScanStatus int         `json:"scan_status"` //  状态，每个位表示响应类型的扫描是否完成，0 表示没有做，1表示做了
	PortInfos  []*PortInfo `json:"port_infos" gorm:"foreignkey:ID;references:ID"`
}

// 端口信息
type PortInfo struct {
	ID         uint   `gorm:"primarykey"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol" gorm:"type:varchar(20)"` // 协议
	ShortName  string `json:"short_name" gorm:"type:varchar(30)"`
	Des        string `json:"des" gorm:"type:varchar(500)"`
	ScanStatus int    `json:"scan_status"` //  状态，每个位表示响应类型的扫描是否完成，0 表示没有做，1表示做了
}

func init() {
	util.RegInitFunc(func() {
		util.InitModle(&PortInfo{}, &ScanIpInfo{}, &Domains{}, &Task{})
	})
}
