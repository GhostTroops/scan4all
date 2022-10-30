package database

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/hktalent/jaeles/database/models"
	"strings"
)

// ImportBurpCollab used to init some default config
func ImportBurpCollab(burpcollab string) string {
	var conObj models.Configuration
	DB.Where(models.Configuration{Name: "BurpCollab"}).Assign(models.Configuration{Value: burpcollab}).FirstOrCreate(&conObj)
	ImportBurpCollabResponse(burpcollab, "")
	return burpcollab
}

// GetDefaultBurpCollab update default sign
func GetDefaultBurpCollab() string {
	var conObj models.Configuration
	DB.Where("name = ?", "BurpCollab").First(&conObj)
	return conObj.Value
}

// ImportBurpCollabResponse used to init some default config
func ImportBurpCollabResponse(burpcollab string, data string) string {
	burpcollabres := data
	if burpcollabres == "" {
		url := fmt.Sprintf("http://%v?original=true", burpcollab)
		resp, err := resty.New().R().Get(url)
		if err != nil {
			return ""
		}
		burpcollabres = string(resp.Body())
		burpcollabres = strings.Replace(burpcollabres, "<html><body>", "", -1)
		burpcollabres = strings.Replace(burpcollabres, "</body></html>", "", -1)
	}

	var conObj models.Configuration
	DB.Where(models.Configuration{Name: "BurpCollabResponse"}).Assign(models.Configuration{Value: burpcollabres}).FirstOrCreate(&conObj)
	return burpcollabres
}

// GetDefaultBurpRes update default sign
func GetDefaultBurpRes() string {
	var conObj models.Configuration
	DB.Where("name = ?", "BurpCollabResponse").First(&conObj)
	return conObj.Value
}

// InitConfigSign used to init some default config
func InitConfigSign() {
	conObj := models.Configuration{
		Name:  "DefaultSign",
		Value: "*",
	}
	DB.Create(&conObj)
}

// GetDefaultSign update default sign
func GetDefaultSign() string {
	var conObj models.Configuration
	DB.Where("name = ?", "DefaultSign").First(&conObj)
	return conObj.Value
}

// UpdateDefaultSign update default sign
func UpdateDefaultSign(sign string) {
	var conObj models.Configuration
	DB.Where("name = ?", "DefaultSign").First(&conObj)
	conObj.Value = sign
	DB.Save(&conObj)
}

// UpdateDefaultBurpCollab update default burp collab
func UpdateDefaultBurpCollab(collab string) {
	var conObj models.Configuration
	DB.Where("name = ?", "BurpCollab").First(&conObj)
	conObj.Value = collab
	DB.Save(&conObj)
}
