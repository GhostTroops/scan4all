package models

// Dummy just testing table
type Dummy struct {
	Model

	Name string `gorm:"type:varchar(30);"`
	Desc string `gorm:"type:varchar(30);"`
}
