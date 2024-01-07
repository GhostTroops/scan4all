package common

import (
	util "github.com/hktalent/go-utils"
	"os"
)

// 通用的、常规小工具参数接收和处理
// 接收命令行 os.Args[1:]
// 接收管道命令，按行输入
func DoCommontools4Chan() chan *string {
	var a []string
	var out = make(chan *string)
	if 1 < len(os.Args) {
		a = os.Args[1:]
		go func() {
			for _, x := range a {
				out <- &x
			}
			close(out)
		}()
	} else {
		// ReadStdIn 内 close
		go util.ReadStdIn(out) // 必须 移步
	}
	return out
}

// 通用的、常规小工具参数接收和处理
// 接收命令行 os.Args[1:]
// 接收管道命令，按行输入
func DoCommontools(cbk func(string, *util.SizedWaitGroup), cTs ...*chan struct{}) {
	var out = DoCommontools4Chan()
	var wg = util.NewSizedWaitGroup(0)
	bC := nil != cTs && 0 < len(cTs)
	for x := range out {
		if bC {
			*cTs[0] <- struct{}{}
		}
		util.WaitFunc4WgParms(&wg, []any{*x}, func(x2 ...any) {
			if bC {
				defer func() {
					<-*cTs[0]
				}()
			}
			cbk(x2[0].(string), &wg)
		})
	}
	wg.Wait()
}
