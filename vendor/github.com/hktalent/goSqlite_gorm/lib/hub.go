package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	util "github.com/hktalent/go-utils"
	"log"
)

// 构建数据集中处理器
func NewHub() *Hub {
	return &Hub{
		ReceveEventData: make(chan EventData, 50),
		Close:           make(chan struct{}, 1),
	}
}

// 日志输出
func DoLog(szT string, err error, client *Client) {
	if nil == err {
		err = errors.New("")
	}
	szS := fmt.Sprintf("Failed to %s: %+v \n", szT, err)
	if nil != client {
		client.send <- &ResponseData{Status: 400, Message: szS}
	}
	log.Println(szS)
}

// 正确处理响应
func (h *Hub) Ok(client *Client) {
	if nil != client {
		client.send <- &ResponseData{
			Message: "Ok",
			Status:  200,
		}
	}
}

func (h *Hub) FnClose() {
	if nil != h.Close {
		h.Close <- struct{}{}
		close(h.Close)
		h.Close = nil
	}
}

// 泛型 通用类型转换
//
//	通常 i 是 map[string]interface{}
func CvtData[T any](i interface{}, client *Client) *T {
	var t1 T
	//var fzfx = reflect.New(reflect.TypeOf(t1))
	data, err := json.Marshal(i)
	if nil != err {
		DoLog("json.Marshal event data", err, client)
		return nil
	}

	if err := json.Unmarshal(data, &t1); nil != err {
		return nil
	}
	return &t1
	//if err := json.Unmarshal(data, &fzfx); nil != err {
	//	DoLog("json.Marshal event data to MzInfoMod", err, client)
	//	return nil
	//}
	//var t01 = fzfx.Elem().Interface().(T)
	//return &t01
}

func (h *Hub) run() {
	//defer close(h.ReceveEventData)
	for {
		select {
		case <-h.Close:
			return
		case msg, ok := <-h.ReceveEventData: // 接收消息
			if ok {
				switch msg.EventType {
				case SaveRsultInfo:
					var fzfx = CvtData[map[string]interface{}](msg.Data, msg.Client)
					SaveRsult4Ws(msg.EventId, fzfx, nil, h, msg.Client)
				case GetTask: // 0-获取任务，同时更新任务状态
					var fzfx = CvtData[QueryTaskForWs](msg.Data, msg.Client)
					if nil == fzfx {
						continue
					}
					x1 := &ClientOpt{client: msg.Client}
					if 0 < fzfx.Num || "" != fzfx.TaskIds {
						x1.QueryTask(fzfx)
					}
				case SaveFinger: // 1-保存指纹命中信息，包含poc列表
					SaveFgData(&msg)
				default:
					log.Println("not supported type: ", msg.EventType)
				}
			}
		}
	}
}

// 保存指纹识别情况数据
func SaveFgData(msg *EventData) {
	var fzfx = CvtData[MzInfoMod](msg.Data, msg.Client)
	if nil == fzfx {
		log.Println("没有正确转换MzInfoMod")
		return
	}
	// 相同任务只出现一条
	if 0 >= util.Update[MzInfoMod](fzfx, fzfx.TaskId, "task_id") {
		if 0 >= util.Create[MzInfoMod](fzfx) {
			DoLog("save data to MzInfoMod RowsAffected is 0", nil, msg.Client)
		} else {
			//h.Ok(msg.Client)
		}
	}
}
