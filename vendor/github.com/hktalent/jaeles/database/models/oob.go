package models

// OutOfBand table to store all OOB data
type OutOfBand struct {
	Model
	Secret            string `gorm:"type:varchar(255);"`
	InteractionString string `gorm:"type:varchar(255);"`
	Protocol          string `gorm:"type:varchar(255);"`
	ClientIP          string `gorm:"type:varchar(255);"`
	Time              string `gorm:"type:varchar(255);"`
	Data              string `gorm:"type:longtext;"`
	Type              string `gorm:"type:varchar(255);default:'burp'"`
}

// ReqLog table to store request have OOB payload
type ReqLog struct {
	Model
	Req               string `gorm:"type:longtext;"`
	Res               string `gorm:"type:longtext;"`
	ScanID            string `gorm:"type:longtext;"`
	InteractionString string `gorm:"type:varchar(255);"`
	Secret            string `gorm:"type:varchar(255);"`
	Data              string `gorm:"type:longtext;"`
	Count             int    `gorm:"type:int;"`
}
