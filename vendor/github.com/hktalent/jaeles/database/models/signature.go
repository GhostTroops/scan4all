package models

// Signature mapping signature to a db
type Signature struct {
	Model
	SignID   string `gorm:"type:varchar(100);unique_index"`
	Name     string `gorm:"type:varchar(100);default:'single'"`
	Category string `gorm:"type:varchar(100);default:'general'"`
	Risk     string `gorm:"type:varchar(100);default:'Info'"`
	Tech     string `gorm:"type:varchar(100);default:'general'"`
	OS       string `gorm:"type:varchar(100);default:'general'"`
	AsbPath  string `gorm:"type:longtext;default:''"`

	Type string `gorm:"type:varchar(30);not null;default:'single'"`
}
