package engine

import (
	"github.com/hktalent/scan4all/lib/util"
	"github.com/hktalent/scan4all/pocs_go"
	"log"
)

// 引擎总入口
func init() {
	util.RegInitFunc(func() {
		// 异步启动一个线程处理检测，避免
		go func() {
			//nMax := 120 // 等xxx秒都没有消息进入就退出
			//nCnt := 0
			for {
				select {
				case <-util.Ctx_global.Done():
					close(util.PocCheck_pipe)
					return
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
