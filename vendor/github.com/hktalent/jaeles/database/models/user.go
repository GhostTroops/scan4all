package models

// User define user table in db
type User struct {
	Model
	Username string `gorm:"type:varchar(255);"`
	Password string `gorm:"type:varchar(255);"`
	Email    string `gorm:"type:varchar(255);"`
	Secret   string `gorm:"type:varchar(255);"`
	Token    string `gorm:"type:varchar(255);"`
}
