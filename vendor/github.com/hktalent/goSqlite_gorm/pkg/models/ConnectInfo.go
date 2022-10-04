package models

import (
	"gorm.io/gorm"
)

// 常用安全术语库
type SafetyTerm struct {
	ID        uint   `json:"id" gorm:"primarykey"`
	ShortSame string `json:"short_same" gorm:"index;type:varchar(50);`
	EnName    string `json:"en_same" gorm:"index;type:varchar(500);`
	CnName    string `json:"cn_same" gorm:"index;type:varchar(500);`
}

// domain info
type DomainInfo struct {
	gorm.Model
	Name string   `json:"name" gorm:"unique_index;type:varchar(300);"`
	Ips  []IpInfo `json:"ips" gorm:"foreignKey:ip;references:name"`
}

// 连接信息
type ConnectInfo struct {
	gorm.Model
	Pid    string `json:"pid" gorm:"type:varchar(10);"`
	Ip     string `json:"ip" gorm:"type:varchar(50);"`
	Cmd    string `json:"cmd" gorm:"type:varchar(5000);"`
	IpInfo IpInfo `json:"ipInfo" gorm:"foreignkey:ip;references:ip"`
}

//func init() {
//	util.RegInitFunc(func() {
//		util.GetDb()
//		util.InitModle(&DomainInfo{}, &ConnectInfo{})
//	})
//}
