package models

import "gorm.io/gorm"

// 域名
type DomainSite struct {
	gorm.Model
	Title string `json:"title"`
	Url   string `json:"url"` // 第一个页面，也是根页面，可能时跳转后的路径
}
