package lib

type EventType int

const (
	GetTask       EventType = 0 // 事件类型：0-获取任务，同时更新任务状态
	SaveFinger    EventType = 1 // 事件类型：1-保存指纹命中信息，包含poc列表
	SaveRsultInfo EventType = 2 // 事件类型：2-保存命中后的结果信息
)

// 客户端请求的事件数据
type EventData struct {
	EventType EventType   `json:"event_type"` // 事件类型：0-获取任务，同时更新任务状态；1-保存指纹命中信息，包含poc列表
	Data      interface{} `json:"data"`       // 事件数据
	Client    *Client     `json:"client"`     // client
	EventId   string      `json:"event_id"`   // 事件id，在请求时带上，响应时关联
}

// 响应
type ResponseData struct {
	EventId string      `json:"event_id"` // 事件id，在请求时带上，响应时关联
	Status  int         `json:"status"`   // 200 is ok,400 is err
	Message interface{} `json:"message"`  // 消息
}

// 单实例 Hub
type Hub struct {
	ReceveEventData chan EventData
	Close           chan struct{}
}

// ws 查询任务容量，保存成功的任务结果
type QueryTaskForWs struct {
	SaveTaskStatus `json:",inline"`
	EventId        string `json:"event_id"` // 事件id，在请求时带上，响应时关联
	Num            int    `json:"num"`      // 剩余任务容量，也是查询任务的个数
}

const (
	Ws_Header_Key   = "51pwn"
	Ws_Header_Value = "A579C748-41BE-493C-9F19-DF08320F8711"
)
