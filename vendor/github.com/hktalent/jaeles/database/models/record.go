package models

// Record define record table in db
type Record struct {
	Model
	ReqURL    string `gorm:"type:longtext;"`
	ReqMethod string `gorm:"type:varchar(30);"`
	ReqBody   string `gorm:"type:longtext;"`
	ReqRaw    string `gorm:"type:longtext;"`

	StatusCode  int     `gorm:"type:int;"`
	ResBody     string  `gorm:"type:longtext;"`
	ResTime     float64 `gorm:"type:float64;"`
	ResLength   int     `gorm:"type:int;"`
	ResRaw      string  `gorm:"type:longtext;"`
	Issues      string  `gorm:"type:varchar(100);"`
	Risk        string  `gorm:"type:varchar(100);"`
	ExtraOutput string  `gorm:"type:longtext;"`
	ScanID      string  `gorm:"type:longtext;"`
	// Issues     []string `gorm:"type:varchar(100);"`

	RawFile string `gorm:"type:longtext"`
	// ChechSum string `gorm:"type:varchar(30);unique_index"`
}
