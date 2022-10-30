package core

import (
	"github.com/hktalent/jaeles/utils"
	"time"

	"github.com/hktalent/jaeles/libs"
)

// Background main function to call other background task
func Background(options libs.Options) {
	utils.DebugF("Checking backround task")
	time.Sleep(time.Duration(options.Refresh) * time.Second)

	// @NOTE: disable for now
	//PollingLog()
	//PickupLog(options)
	// @TODO: Add passive signature for analyzer each request
}

//
//// PollingLog polling all request with their
//func PollingLog() {
//	objs := database.GetUnPollReq()
//	for _, obj := range objs {
//		// sending part
//		secret := url.QueryEscape(database.GetSecretbyCollab(obj.Secret))
//		URL := fmt.Sprintf("http://polling.burpcollaborator.net/burpresults?biid=%v", secret)
//		resp, err := resty.New().R().Get(URL)
//		if err != nil {
//			continue
//		}
//		response := string(resp.Body())
//
//		jsonParsed, _ := gabs.ParseJSON([]byte(response))
//		exists := jsonParsed.Exists("responses")
//		if exists == false {
//			continue
//		} else {
//			for _, element := range jsonParsed.Path("responses").Children() {
//				// import this to DB so we don't miss in other detect
//				database.ImportOutOfBand(fmt.Sprintf("%v", element))
//			}
//		}
//	}
//}
//
//// PickupLog pickup request that's have log coming back
//func PickupLog(options libs.Options) {
//	objs := database.GetUnPollReq()
//	for _, obj := range objs {
//		interactString := obj.InteractionString
//		data := database.GetOOB(interactString)
//		if data != "" {
//			var rec libs.Record
//			rec.Request.Beautify = obj.Req
//			rec.Response.Beautify = obj.Res
//			rec.ExtraOutput = data
//
//			if options.NoOutput == false {
//				outputName := StoreOutput(rec, options)
//				rec.RawOutput = outputName
//				database.ImportRecord(rec)
//			}
//
//		}
//	}
//}
