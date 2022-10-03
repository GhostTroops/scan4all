package engine

import (
	"context"
	"github.com/codegangsta/inject"
	"github.com/hktalent/goSqlite_gorm/pkg/models"
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pocs_go"
	"github.com/panjf2000/ants/v2"
	"log"
	"sync"
)

// 引擎对象，全局单实例
type Engine struct {
	Context   *context.Context       // 上下文
	Wg        *sync.WaitGroup        // Wg
	Pool      int                    // 线程池
	PoolFunc  *ants.PoolWithFunc     // 线程调用
	EventData chan *models.EventData // 数据队列
}

// 全局引擎
var G_Engine *Engine

// 创建引擎
//  默认每个 goroutine 占用 8KB 内存
//  一台 8GB 内存的机器满打满算也只能创建 8GB/8KB = 1000000 个 goroutine
//  更何况系统还需要保留一部分内存运行日常管理任务，go 运行时需要内存运行 gc、处理 goroutine 切换等
func NewEngine(c *context.Context, pool int) *Engine {
	if nil != G_Engine {
		return G_Engine
	}
	G_Engine = &Engine{Context: c, Wg: util.Wg, Pool: pool, EventData: make(chan *models.EventData, pool)}

	p, err := ants.NewPoolWithFunc(pool, func(i interface{}) {
		defer G_Engine.Wg.Done()
		G_Engine.DoEvent(i.(*models.EventData))
	})
	if nil != err {
		log.Println("ants.NewPoolWithFunc is error: ", err)
	}
	G_Engine.PoolFunc = p

	return G_Engine
}

// 释放资源
func (e *Engine) Close() {
	defer ants.Release()
	e.PoolFunc.Release()
	e.Wg.Wait()
}

// case 扫描使用的函数
func (e *Engine) DoCase(ed *models.EventData) interface{} {
	if i, ok := CaseScanFunc[ed.EventType]; ok {
		return i
	}
	return nil
}

// 执行事件代码 内部用
//  每个事件自己做防重处理
//  每个事件异步执行
//  每种事件类型可以独立控制并发数
func (e *Engine) DoEvent(ed *models.EventData) {
	var x01 = &models.EventData{}
	if nil != x01 {
	}
	if nil != ed {
		fnCall := e.DoCase(ed)
		if nil != fnCall {
			in := inject.New()
			for _, i := range ed.EventData {
				in.Map(i)
			}
			v, err := in.Invoke(fnCall)
			if nil != err {
				log.Printf("DoEvent %d is error: %v %+v \n", ed.EventType, err, ed.EventData)
			} else if nil != v {
				log.Printf("DoEvent result %s %v\n", ed.EventType, v)
			}
		} else {
			log.Printf("can case func %v\n", ed)
		}
	}
}

// 引擎总入口
func init() {
	util.RegInitFunc(func() {
		x1 := NewEngine(&util.Ctx_global, util.GetValAsInt("ScanPoolSize", 5000))
		// 异步启动一个线程处理检测，避免
		util.Wg.Add(1)
		go func() {
			defer func() {
				x1.Close()
				util.Wg.Done()
			}()
			//nMax := 120 // 等xxx秒都没有消息进入就退出
			//nCnt := 0
			for {
				select {
				case <-util.Ctx_global.Done():
					close(util.PocCheck_pipe)
					return
				case x2 := <-G_Engine.EventData: // 各种扫描的控制
					if nil != x2 {
						G_Engine.Wg.Add(1)
						G_Engine.PoolFunc.Invoke(x2)
					}
				case x1, ok := <-util.PocCheck_pipe:
					if util.GetValAsBool("NoPOC") || nil == x1 || !ok {
						//close(util.PocCheck_pipe) // 这行会在 NoPOC该标志开启时，其他进程无法传递过来而出错
						log.Println("go_poc_checkout is over")
						continue
					}
					//nCnt = 0
					log.Printf("<-lib.PocCheck_pipe: %+v  %s", *x1.Wappalyzertechnologies, x1.URL)
					util.DoSyncFunc(func() {
						func(x99 *util.PocCheck) {
							pocs_go.POCcheck(*x99.Wappalyzertechnologies, x99.URL, x99.FinalURL, x99.Checklog4j)
						}(x1)
					})
				default:
					util.DoDelayClear()
					util.DoSleep()
					//var f01 float32 = float32(nCnt) / float32(nMax) * float32(100)
					//fmt.Printf(" Asynchronous go PoCs detection task %%%0.2f ....\r", f01)
					//<-time.After(time.Duration(1) * time.Second)
					//nCnt += 1
					//if nMax <= nCnt {
					//	close(util.PocCheck_pipe)
					//	return
					//}
				}
			}
		}()
	})
}
