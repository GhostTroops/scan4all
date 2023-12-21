package engine

import (
	"context"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/lib"
	"github.com/GhostTroops/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pocs_go"
	"github.com/panjf2000/ants/v2"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
)

// 引擎对象，全局单实例
type Engine struct {
	Context      *context.Context       // 上下文
	Wg           *sync.WaitGroup        // Wg
	Pool         int                    // 线程池
	PoolFunc     *ants.PoolWithFunc     // 线程调用
	EventData    chan *models.EventData // 数据队列
	caseScanFunc sync.Map
}

var G_Engine *Engine

// 创建引擎
//
//	默认每个 goroutine 占用 8KB 内存
//	一台 8GB 内存的机器满打满算也只能创建 8GB/8KB = 1000000 个 goroutine
//	更何况系统还需要保留一部分内存运行日常管理任务，go 运行时需要内存运行 gc、处理 goroutine 切换等
func NewEngine(c *context.Context, pool int) *Engine {
	if nil != util.G_Engine {
		return util.G_Engine.(*Engine)
	}
	x1 := &Engine{Context: c, Wg: &sync.WaitGroup{}, Pool: pool, EventData: make(chan *models.EventData, pool)}
	p, err := ants.NewPoolWithFunc(pool, func(i interface{}) {
		defer x1.Wg.Done()
		x1.DoEvent(i.(*models.EventData))
	})
	if nil != err {
		log.Println("ants.NewPoolWithFunc is error: ", err)
	}
	x1.PoolFunc = p
	util.G_Engine = x1
	G_Engine = x1
	util.EngineFuncFactory = x1.EngineFuncFactory
	util.SendEvent = x1.SendEvent
	log.Println("Engine init ok")
	return x1
}

func (e *Engine) EngineFuncFactory(nT int64, fnCbk interface{}) {
	e.RegCaseScanFunc(nT, fnCbk)
}

func (e *Engine) RegCaseScanFunc(nType int64, fnCbk interface{}) {
	e.caseScanFunc.Store(nType, fnCbk)
}

func (r *Engine) GetCaseScanFunc() *sync.Map {
	return &r.caseScanFunc
}

// 释放资源
func (e *Engine) Close() {
	defer ants.Release()
	e.PoolFunc.Release()
	e.Wg.Wait()
}

// case 扫描使用的函数
func (e *Engine) DoCase(ed *models.EventData) util.EngineFuncType {
	if i, ok := e.caseScanFunc.Load(ed.EventType); ok {
		return i.(util.EngineFuncType)
	}
	return nil
}

// 关联发送若干个事件
func (e *Engine) SendEvent(evt *models.EventData, argsTypes ...int64) {
	for _, i := range argsTypes {
		var n1 = models.EventData{}
		util.DeepCopy(evt, &n1)
		n1.EventType = i
		e.EventData <- &n1
	}
}

// 执行事件代码 内部用
//
//	每个事件自己做防重处理
//	每个事件异步执行
//	每种事件类型可以独立控制并发数
func (e *Engine) DoEvent(ed *models.EventData) {
	if nil != ed && nil != ed.EventData && 0 < len(ed.EventData) {
		fnCall := e.DoCase(ed)
		if nil != fnCall {
			fnCall(ed, ed.EventData...)
		} else {
			log.Printf("can not find fnCall case func %v\n", ed)
		}
	}
}

func (x1 *Engine) Running() {
	// 异步启动一个线程处理检测，避免
	go func() {
		defer func() {
			x1.Close()
		}()
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		tK := time.NewTicker(2 * time.Second)
		defer tK.Stop()
		//nMax := 120 // 等xxx秒都没有消息进入就退出
		//nCnt := 0
		for {
			select {
			case <-util.Ctx_global.Done():
				close(util.PocCheck_pipe)
				return
			case <-c:
				util.DoCbk("exit")
				os.Exit(1)
			case x2 := <-x1.EventData: // 各种扫描的控制
				if nil != x2 && nil != x2.EventData {
					x1.Wg.Add(1)
					x1.PoolFunc.Invoke(x2)
				}
			case x1, ok := <-util.PocCheck_pipe:
				if util.GetValAsBool("NoPOC") || nil == x1 || !ok {
					//close(util.PocCheck_pipe) // 这行会在 NoPOC该标志开启时，其他进程无法传递过来而出错
					log.Println("go_poc_checkout is over")
					continue
				}
				//nCnt = 0
				if !util.TestRepeat(x1, *x1.Wappalyzertechnologies, x1.URL) {
					log.Printf("<-util.PocCheck_pipe: %+v  %s", *x1.Wappalyzertechnologies, x1.URL)
					func(x99 *util.PocCheck) {
						util.DoSyncFunc(func() {
							pocs_go.POCcheck(*x99.Wappalyzertechnologies, x99.URL, x99.FinalURL, x99.Checklog4j)
						})
					}(x1)
				}
			case <-tK.C:
				util.DoDelayClear(x1.Wg) // panic: sync: WaitGroup misuse: Add called concurrently with Wait
			}
		}
	}()
}

// 引擎总入口
func init() {
	//log.Println("engineImp.go run")
	lib.GConfigServer.OnClient = true
	util.RegInitFunc4Hd(func() {
		// 下面的变量 不能移动到DoSyncFunc，否则全局变量将影响后续的init，导致无效的内存
		NewEngine(&util.Ctx_global, util.GetValAsInt("ScanPoolSize", 5000))

		util.DoSyncFunc(func() {
			util.G_Engine.(*Engine).Running()
		})
	})
}
