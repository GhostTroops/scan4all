package pool

import (
	"testing"
	"time"
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

func TestStopUnblocksInputSender(t *testing.T) {
	p := NewPool(2)
	p.Function = func(value interface{}) interface{} {
		return value
	}
	p.RunBack()

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		for range p.Out {
		}
	}()

	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for i := 0; i < 10; i++ {
			select {
			case <-p.Stopped():
				p.InDone()
				return
			case p.In <- i:
			}
		}
		p.InDone()
	}()

	p.Stop()
	select {
	case <-senderDone:
	case <-time.After(time.Second):
		t.Fatal("input sender remained blocked after stop")
	}

	waitDone := make(chan struct{})
	go func() {
		p.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("workers did not stop")
	}
	<-outDone
}
