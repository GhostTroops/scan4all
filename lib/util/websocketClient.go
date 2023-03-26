package util

import (
	"bytes"
	"compress/flate"
	"fmt"
	"github.com/gorilla/websocket"
	util "github.com/hktalent/go-utils"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	E2eServer = "e2e.51pwn.com"
	WriteWait = 10 * time.Second
	BufSize   = 100 * 1024
)

type E2eImp struct {
	lock      *sync.Mutex
	Type      string // A/C
	Key       string
	hd        *map[string]string
	Socks5Ips string
	OfferOk   bool
	AnswerOk  bool
	Ws        *E2eWebsocket
	ReTryWs   chan struct{}
}

// 客户端请求的事件数据
type EventData struct {
	EventType int         `json:"event_type"` // 事件类型：0-获取任务，同时更新任务状态；1-保存指纹命中信息，包含poc列表
	Data      interface{} `json:"data"`       // 事件数据
}
type WsData struct {
	Hd   *map[string]string `json:"hd"`
	Data interface{}        `json:"data"`
}

type E2eWebsocket struct {
	Conn   *websocket.Conn
	E2eImp *E2eImp
}

// 响应
type ResponseData struct {
	EventId string      `json:"event_id"` // 事件id，在请求时带上，响应时关联
	Status  int         `json:"status"`   // 200 is ok,400 is err
	Message interface{} `json:"message"`  // 消息
}

func (r *E2eWebsocket) SendData(data *WsData) error {
	r.Conn.SetWriteDeadline(time.Now().Add(WriteWait * 60))
	return r.Conn.WriteJSON(&EventData{EventType: 'e', Data: data})
}

// io.NopCloser(bytes.NewReader(
func (r *E2eWebsocket) DispatchEvt(data []byte) {
	DefaultPool.Submit(func() {
		a11 := bytes.Split(data, []byte("\n"))
		for _, x11 := range a11 {
			var o = &ResponseData{}
			if 3 > len(x11) { // skip empy line
				continue
			}
			if err := json.Unmarshal(x11, o); nil == err {
				if d1, err := json.Marshal(o.Message); nil == err && 2 < len(d1) { // skip ""
					switch o.EventId {
					//case Sdp:
					//	r.E2eImp.SessionDescriptionCbk(io.NopCloser(bytes.NewReader(d1)))
					//	break
					//default:
					//r.E2eImp.CandidateCbk(io.NopCloser(bytes.NewReader(d1)))
					}
				} else if 2 < len(d1) {
					Logs("json.Marshal(o.Message)", err, string(d1))
				}
			} else {
				Logs("DispatchEvt", err, string(data))
			}
		}
	})
}

func DoWebSocket(r *E2eImp) (*E2eWebsocket, error) {
	szUrl := "wss://" + E2eServer + "/rmtClientWss"
	u, err := url.Parse(szUrl)
	if err != nil {
		return nil, err
	}

	rawConn, err := net.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}

	wsHeaders := http.Header{
		"Origin":     {szUrl},
		"User-Agent": {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15"},
		"51pwn":      {"A579C748-41BE-493C-9F19-DF08320F8711"},
		"k":          {r.Key},
		// your milage may differ
		"Sec-WebSocket-Extensions": {"permessage-deflate; client_max_window_bits, x-webkit-deflate-frame"},
	}
	d := websocket.Dialer{
		ReadBufferSize:    BufSize,
		WriteBufferSize:   BufSize,
		EnableCompression: true,
		NetDial: func(net, addr string) (net.Conn, error) {
			return rawConn, nil
		},
	}
	wsConn, resp, err := d.Dial(u.String(), wsHeaders)
	if err != nil {
		return nil, fmt.Errorf("websocket.NewClient Error: %s\nResp:%+v", err, resp)
	}
	wsConn.SetCompressionLevel(flate.BestCompression)
	x := &E2eWebsocket{Conn: wsConn, E2eImp: r}
	util.DoSyncFunc(func() {
		defer func() {
			wsConn.Close()
			if err := recover(); nil != err {
				r.ReTryWs <- struct{}{}
			}
		}()
		for {
			select {
			case <-util.Ctx_global.Done():
				return
			default:
				if t, message, err := wsConn.ReadMessage(); nil == err {
					x.DispatchEvt(message)
				} else { // *net.OpError
					log.Println("wsConn.ReadMessage", t, err)
				}
			}
		}
	})
	return x, nil
}
