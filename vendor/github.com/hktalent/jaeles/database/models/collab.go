package models

// Collab store all collab server
type Collab struct {
	Model
	Secret            string `gorm:"type:varchar(255);"`
	InteractionString string `gorm:"type:varchar(255);"`
	Type              string `gorm:"type:varchar(255);default:'burp'"`
}
