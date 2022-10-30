package database

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/hktalent/jaeles/libs"

	"github.com/Jeffail/gabs/v2"
	"github.com/hktalent/jaeles/database/models"
)

// GetCollab get random collab to test
func GetCollab() string {
	var collabs []models.Collab
	DB.Find(&collabs)
	if len(collabs) == 0 {
		// auto gen a new one using request bin
		// dnsbin := NewDNSBin()
		// if dnsbin != "" {
		// 	return dnsbin
		// }
		return ""
	}
	rand.Seed(time.Now().Unix())
	n := rand.Int() % len(collabs)
	return collabs[n].InteractionString
}

// GetSecretbyCollab get secret by interactString
func GetSecretbyCollab(InteractionString string) string {
	var collabs models.Collab
	// DB.Find(&collabs)
	DB.Where("interaction_string = ?", InteractionString).First(&collabs)
	return collabs.Secret
}

// CleanCollab clean all collab
func CleanCollab() {
	var rec []models.Collab
	DB.Find(&rec)
	DB.Unscoped().Delete(&rec)
}

// ImportCollab import burp collab with it's secret
func ImportCollab(secret string, InteractionString string) {
	recObj := models.Collab{
		Secret:            secret,
		InteractionString: InteractionString,
	}
	DB.Create(&recObj)
}

// GetOOB check oob log with interactString
func GetOOB(InteractionString string) string {
	var oob models.OutOfBand
	DB.Where("interaction_string = ?", InteractionString).First(&oob)
	return oob.Data
}

// ImportOutOfBand import polling result to DB
func ImportOutOfBand(data string) {
	jsonParsed, _ := gabs.ParseJSON([]byte(data))
	clientIP := jsonParsed.Path("client").Data().(string)
	protocol := jsonParsed.Path("protocol").Data().(string)
	ts := jsonParsed.Path("time").Data().(string)
	rawData := fmt.Sprintf("%v", jsonParsed.Path("data"))

	interactionString := jsonParsed.Path("interactionString").Data().(string)
	secret := GetSecretbyCollab(interactionString)

	// interactionString
	recObj := models.OutOfBand{
		InteractionString: interactionString,
		ClientIP:          clientIP,
		Time:              ts,
		Protocol:          protocol,
		Data:              rawData,
		Secret:            secret,
	}
	DB.Create(&recObj)
}

// GetUnPollReq get request that unpoll
func GetUnPollReq() []models.ReqLog {
	var reqLogs []models.ReqLog
	DB.Where("data = ?", "").Find(&reqLogs)
	return reqLogs
}

// ImportReqLog import polling result to DB
func ImportReqLog(rec libs.Record, analyzeString string) {
	secret := GetSecretbyCollab(analyzeString)
	recObj := models.ReqLog{
		Req:               rec.Request.Beautify,
		Res:               rec.Response.Beautify,
		InteractionString: analyzeString,
		ScanID:            rec.ScanID,
		Secret:            secret,
	}
	DB.Create(&recObj)
}
