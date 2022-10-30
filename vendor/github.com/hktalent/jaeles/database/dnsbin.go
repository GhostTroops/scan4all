package database

// Use to gen bunch of DNS on  dns.requestbin.net

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/gorilla/websocket"
)

// NewDNSBin create new dnsbin
func NewDNSBin() string {
	var dnsbin string
	// var .fbbbf336914aa6bd9b58.d.requestbin.net
	addr := "dns.requestbin.net:8080"
	u := url.URL{Scheme: "ws", Host: addr, Path: "/dns"}

	// init a connection
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return ""
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				return
			}
			jsonParsed, err := gabs.ParseJSON([]byte(message))
			if err != nil {
				return
			}
			// jsonParsed.Path("master")
			prefix := strconv.FormatInt(time.Now().Unix(), 10)
			token := strings.Trim(fmt.Sprintf("%v", jsonParsed.Path("master")), `"`)
			dnsbin = fmt.Sprintf("%v.%v.d.requestbin.net", prefix, token)
			return
		}
	}()

	err = c.WriteMessage(websocket.TextMessage, []byte(``))
	if err != nil {
		return dnsbin
	}
	time.Sleep(time.Second)
	c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	return dnsbin
}

// GetTS get current timestamp and return a string
func GetTS() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}
