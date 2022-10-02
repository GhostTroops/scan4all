package lib

import (
	"bytes"
	"encoding/json"
	"github.com/hktalent/websocket"
	"log"
	"time"
)

const (
	// Time allowed to write a message to the peer.0表示不超时
	WriteWait = 10 * time.Second
	// Time allowed to read the next pong message from the peer.
	PongWait = 60 * time.Second
	// 54秒ping一次，Send pings to peer with this period. Must be less than PongWait.
	PingPeriod = (PongWait * 9) / 10
	// 5M
	SizeLimit   int = 1024 * 1024 * 5
	EnableClose     = false // 打开自动关闭ws功能，默认不关闭，长链接提高性能
)

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub
	// The websocket connection.
	conn *websocket.Conn
	// Buffered channel of outbound messages.
	send chan *ResponseData
}

// 读取来自客户端的数据
func (c *Client) readPump() {
	defer func() {
		c.conn.Close()
		//c.hub.FnClose()
		//close(c.send) // 不能关闭，否则会导致异常退出
	}()
	c.conn.SetReadLimit(int64(SizeLimit))
	c.conn.SetReadDeadline(time.Now().Add(PongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(PongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				DoLog("conn.ReadMessage", err, c)
			}
			break
		}
		message = bytes.TrimSpace(message)
		var ed = EventData{}
		if err := json.Unmarshal(message, &ed); nil != err {
			DoLog("json.Unmarshal", err, c)
			continue
		}
		ed.Client = c
		c.hub.ReceveEventData <- ed
	}
}

// 给客户端响应数据
func (c *Client) writePump() {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		//c.conn.Close()
		//c.hub.FnClose()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				log.Print(err)
				return
			}
			data, _ := json.Marshal(message)
			w.Write(data)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				data, _ = json.Marshal(<-c.send)
				w.Write(data)
			}
			if EnableClose {
				if err := w.Close(); err != nil {
					return
				}
			}
		case <-ticker.C: // ping 保持连接
			c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
