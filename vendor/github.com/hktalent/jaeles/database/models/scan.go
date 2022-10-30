package models

// Scans store scan log
type Scans struct {
	Model
	ScanID      string `gorm:"type:varchar(255);"`
	ScanName    string `gorm:"type:varchar(255);"`
	SignatureID string `gorm:"type:varchar(255);"`
	Input       string `gorm:"type:longtext;default:''"`
	OutputDir   string `gorm:"type:longtext;"`
	Mode        string `gorm:"type:varchar(255);default:'scan'"`
	Level       int    `gorm:"type:int;default:'1'"`
	Source      string `gorm:"type:longtext;default:''"`
}
