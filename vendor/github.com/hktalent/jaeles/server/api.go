package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hktalent/jaeles/database"
	"github.com/hktalent/jaeles/database/models"
)

// Ping testing authenticated connection
func Ping(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "200",
		"message": "pong",
	})
}

// GetStats return stat data
func GetStats(c *gin.Context) {
	var info []models.Record
	database.DB.Where("risk = ?", "Info").Find(&info)
	var potential []models.Record
	database.DB.Where("risk = ?", "Potential").Find(&potential)
	var low []models.Record
	database.DB.Where("risk = ?", "Low").Find(&low)
	var medium []models.Record
	database.DB.Where("risk = ?", "Medium").Find(&medium)
	var high []models.Record
	database.DB.Where("risk = ?", "High").Find(&high)
	var critical []models.Record
	database.DB.Where("risk = ?", "Critical").Find(&critical)

	stats := []int{
		len(info),
		len(potential),
		len(low),
		len(medium),
		len(high),
		len(critical),
	}

	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Success",
		"stats":   stats,
	})
}

// GetSignSummary return signature stat
func GetSignSummary(c *gin.Context) {
	var signs []models.Signature
	var categories []string
	var data []int
	database.DB.Find(&signs).Pluck("DISTINCT category", &categories)
	// stats := make(map[string]int)
	for _, category := range categories {
		var signatures []models.Signature
		database.DB.Where("category = ?", category).Find(&signatures)
		data = append(data, len(signatures))
	}

	c.JSON(200, gin.H{
		"status":     "200",
		"message":    "Success",
		"categories": categories,
		"data":       data,
	})
}

// GetSigns return signature record
func GetSigns(c *gin.Context) {
	var signs []models.Signature
	database.DB.Find(&signs)

	c.JSON(200, gin.H{
		"status":     "200",
		"message":    "Success",
		"signatures": signs,
	})
}

// GetAllScan return all scans
func GetAllScan(c *gin.Context) {
	var scans []models.Scans
	database.DB.Find(&scans)

	// remove empty scan
	var realScans []models.Scans
	for _, scan := range scans {
		var rec models.Record
		database.DB.First(&rec, "scan_id = ?", scan.ScanID)
		if rec.ScanID != "" {
			realScans = append(realScans, scan)
		}
	}

	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Success",
		"scans":   realScans,
	})
}

// GetRecords get record by scan ID
func GetRecords(c *gin.Context) {
	sid := c.Param("sid")
	var records []models.Record
	database.DB.Where("scan_id = ?", sid).Find(&records)

	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Success",
		"records": records,
	})
}

// GetRecord get record detail by record ID
func GetRecord(c *gin.Context) {
	rid := c.Param("rid")
	var record models.Record
	database.DB.Where("id = ?", rid).First(&record)

	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Success",
		"record":  record,
	})
}

// SignConfig config
type SignConfig struct {
	Value string `json:"sign"`
}

// UpdateDefaultSign geet record by scan
func UpdateDefaultSign(c *gin.Context) {
	var signConfig SignConfig
	err := c.ShouldBindJSON(&signConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	database.UpdateDefaultSign(signConfig.Value)
	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Update Defeult sign success",
	})
}
