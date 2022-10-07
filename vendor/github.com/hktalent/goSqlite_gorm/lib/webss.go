package lib

import (
	"github.com/hktalent/websocket"
	"net/http"
)

// 初始化参数
var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  SizeLimit,
	WriteBufferSize: SizeLimit,
}

var MyHub *Hub

// 初始化单实例
func init() {
	if !GConfigServer.OnClient {
		MyHub = NewHub()
		go MyHub.run()
	}
}

// websocket处理
func Wshandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(Ws_Header_Key) != Ws_Header_Value {
		return
	}
	conn, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		DoLog("set websocket upgrade", err, nil)
		return
	}
	client := &Client{hub: MyHub, conn: conn, send: make(chan *ResponseData, 256)}
	go client.writePump()
	go client.readPump()
}

// 客户端使用
var SendRmtWs chan *EventData
