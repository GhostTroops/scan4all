package common

import (
	"fmt"
	util "github.com/hktalent/go-utils"
	"strings"
	"sync"
	"time"
)

type channelData struct {
	channel interface{}
	data    interface{}
	wg      *util.SizedWaitGroup
}

// Engine 是通用引擎结构
type Engine struct {
	handlerFuncs map[interface{}]func(interface{})
	dataChannel  chan channelData
	lock         *sync.Mutex
	Close        chan bool
	wg           *util.SizedWaitGroup
}

// NewEngine 创建一个新的引擎实例
func NewEngine() *Engine {
	r := &Engine{
		handlerFuncs: make(map[interface{}]func(interface{})),
		dataChannel:  make(chan channelData, 100000),
		lock:         &sync.Mutex{},
		Close:        make(chan bool),
	}
	r.Start()
	return r
}

func (e *Engine) SetWg(wg *util.SizedWaitGroup) {
	e.wg = wg
}

// Stop 停止引擎
func (e *Engine) Stop() {
	e.Close <- true
	for c, _ := range e.handlerFuncs {
		close(c.(chan interface{}))
		delete(e.handlerFuncs, c)
	}
	close(e.dataChannel)
}

// RegisterHandler 注册处理函数，关联一个通道和处理函数
func (e *Engine) RegisterHandler(channel interface{}, handlerFunc func(interface{})) *Engine {
	e.lock.Lock()
	defer e.lock.Unlock()
	//log.Println(channel)
	e.handlerFuncs[channel] = handlerFunc
	return e
}
func (e *Engine) DoOne(cd channelData) {
	util.WaitFunc4Wg(cd.wg, func() {
		e.handleData(cd.channel, cd.data)
	})
}
func (e *Engine) CheckAllC() int {
	var i = len(e.dataChannel)
	if nil != e.wg {
		i += e.wg.WaitLen()
	}
	return i
}
func (e *Engine) Start() {
	util.Wg.Add(1)
	go func() {
		defer util.Wg.Done()
		var tk = time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-e.Close:
				return
			case <-tk.C:
				n11 := e.CheckAllC()
				if util.GetValAsBool("debug") {
					fmt.Printf("%s wiat for engine:%d%s\r", util.GetNow(), n11, strings.Repeat(" ", 25))
				}
				if 0 == n11 {
					return
				}
			case cd, ok := <-e.dataChannel:
				// 通过注册的处理函数处理数据
				if ok {
					e.DoOne(cd)
					n1 := len(e.dataChannel)
					for i := 0; i < n1; i++ {
						cd, ok = <-e.dataChannel
						if ok {
							e.DoOne(cd)
						}
					}
				} else {
					return
				}
			}
		}
	}()
}

func (e *Engine) handleData(channel interface{}, data interface{}) {
	// 根据注册通道的处理函数处理数据
	if handlerFunc, ok := e.handlerFuncs[channel]; ok {
		handlerFunc(data)
	}
}

// SendData 向引擎发送数据
func (e *Engine) SendData(channel interface{}, data interface{}, wg *util.SizedWaitGroup) *Engine {
	util.WaitFunc4Wg(wg, func() {
		if _, ok := e.handlerFuncs[channel]; ok {
			e.dataChannel <- channelData{channel: channel, data: data, wg: wg}
		} else {
			fmt.Printf("Channel not registered: %+v \n", data)
		}
	})
	return e
}

var ChanEngine *Engine

func init() {
	util.RegInitFunc(func() {
		ChanEngine = NewEngine()
	})
}
