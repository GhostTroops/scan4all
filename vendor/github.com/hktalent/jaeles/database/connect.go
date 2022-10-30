package database

import (
	"github.com/hktalent/jaeles/database/models"
	"github.com/jinzhu/gorm"

	// load driver
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// DB global DB variable
var DB *gorm.DB

// InitDB init DB connection
func InitDB(DBPath string) (*gorm.DB, error) {
	db, err := gorm.Open("sqlite3", DBPath)
	// turn this on when we go live
	// Disable Logger, don't show any log even errors
	db.LogMode(false)

	if err == nil {
		DB = db
		db.AutoMigrate(&models.Scans{})
		db.AutoMigrate(&models.Record{})
		db.AutoMigrate(&models.Signature{})
		db.AutoMigrate(&models.User{})
		db.AutoMigrate(&models.Configuration{})
		db.AutoMigrate(&models.Dummy{})
		// table for Out of band stuff
		db.AutoMigrate(&models.Collab{})
		db.AutoMigrate(&models.OutOfBand{})
		db.AutoMigrate(&models.ReqLog{})
		return db, err
	}
	return nil, err
}
