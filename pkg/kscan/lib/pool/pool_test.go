package pool

import (
	"testing"
)

func TestName(t *testing.T) {
	//NewTask是放到工作池当中运行的函数。使用的时候需要先实例化他
	//w := NewWorker()
	//实例化工作池

	////这里启用另外一个goroutine向worker当中写入，不然会出现all goroutines are asleep，需要从管道中获得一个数据，而这个数据必须是其他goroutine线放入管道的
	//go func() {
	//	for i := 1; i < 100; i++ {
	//		p.Jobs <- w //把需要运行的函数依次放入工作池。
	//	}
	//	close(p.Jobs)
	//}()
	//p.Run()

}
