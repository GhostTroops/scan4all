package util

// 关闭chan
func CloseChan(c chan struct{}) {
	if _, ok := <-c; ok {
		close(c)
	}
}
