package server

import (
	"encoding/base64"
	"fmt"
	"github.com/hktalent/jaeles/utils"
	"net/http"

	"github.com/hktalent/jaeles/libs"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/hktalent/jaeles/core"
)

// RequestData struct for recive request from burp
type RequestData struct {
	RawReq string `json:"req"`
	RawRes string `json:"res"`
	URL    string `json:"url"`
}

// SetBurpCollab setup Burp
func SetBurpCollab(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Got it",
	})
}

// ParseRaw Get Raw Burp Request in base64 encode
func ParseRaw(c *gin.Context) {
	// result <- record
	// core data
	var reqData RequestData
	// c.BindJSON(&reqData)
	err := c.ShouldBindJSON(&reqData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	go func() {
		var record libs.Record
		// core data
		rawReq := reqData.RawReq
		rawRes := reqData.RawRes

		req, err := base64.StdEncoding.DecodeString(rawReq)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "error decode request",
				"status":  "Error",
			})
		}
		record.OriginReq = core.ParseBurpRequest(string(req))
		/* Response part */
		if rawRes != "" {
			// response stuff
			res, err := base64.StdEncoding.DecodeString(rawRes)
			if err != nil {
				c.JSON(500, gin.H{
					"message": "error decode response",
					"status":  "Error",
				})
			}
			record.OriginRes = core.ParseBurpResponse(string(req), string(res))
		}

		color.Green("-- got from gin")
		fmt.Println(record.OriginReq.URL)
		color.Green("-- done from gin")
		// result <- record
	}()

	c.JSON(200, gin.H{
		"status":  "200",
		"message": "Got it",
	})
}

// ReceiveRequest is handler to got  request from Burp
func ReceiveRequest(result chan libs.Record) gin.HandlerFunc {
	return func(c *gin.Context) {
		cCp := c.Copy()
		var reqData RequestData
		err := cCp.ShouldBindJSON(&reqData)
		if err != nil {
			c.JSON(200, gin.H{
				"status":  "500",
				"message": "Error parsing JSON data",
			})
			return
		}
		var record libs.Record
		// core data
		rawReq := reqData.RawReq
		rawRes := reqData.RawRes
		URL := reqData.URL

		// var record libs.Record
		req, err := base64.StdEncoding.DecodeString(rawReq)
		if err != nil {
			c.JSON(200, gin.H{
				"status":  "500",
				"message": "Error parsing request",
			})
			return
		}

		utils.DebugF("Raw req: %v", string(req))

		record.OriginReq = core.ParseBurpRequest(string(req))
		utils.DebugF("Origin Body: %v", record.OriginReq.Body)
		if URL != "" {
			record.OriginReq.URL = URL
		}
		utils.InforF("[Recive] %v %v \n", record.OriginReq.Method, record.OriginReq.URL)

		/* Response part */
		if rawRes != "" {
			// response stuff
			res, err := base64.StdEncoding.DecodeString(rawRes)
			if err != nil {
				c.JSON(200, gin.H{
					"status":  "500",
					"message": "Error parsing response",
				})
			}
			record.OriginRes = core.ParseBurpResponse(string(req), string(res))
		}
		result <- record

		c.JSON(200, gin.H{
			"status":  "200",
			"message": "Got it",
		})
	}

}
