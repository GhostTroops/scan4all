package models

// Configuration used to store some config for entire tools
type Configuration struct {
	Model
	Name  string `gorm:"type:varchar(255);"`
	Value string `gorm:"type:varchar(255);"`
}
