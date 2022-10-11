package main

import (
	"log"
	"mime"
)

func main() {
	log.Println(mime.TypeByExtension(".jsp"))
	//
	//data, err := ioutil.ReadFile("/Users/51pwn/MyWork/TestPoc/JRMPListener.ser")
	//if nil == err {
	//	x1 := socket.NewCheckTarget("http://127.0.0.1:4444", "tcp", 15)
	//	x1.SendPayload(data, 15)
	//	x1.Close()
	//}
	//
	//x1 := PipelineHttp.NewPipelineHttp()
	////x1.ErrLimit = 9999999
	//defer x1.Close()
	//x1.DoGet("https://127.0.0.1:8081/scan4all", func(resp *http.Response, err error, szU string) {
	//	if nil != resp {
	//		log.Println(resp.StatusCode)
	//	}
	//})
	//var Wg = sync.WaitGroup{}
	//// 单独测试没有问题
	//for i := 33; i < 8082; i++ {
	//	Wg.Add(1)
	//	go func(n int) {
	//		defer Wg.Done()
	//		s1 := fmt.Sprintf("http://127.0.0.1:%d/scan4all", n)
	//		if resp, err := util.HttpRequset(s1, "GET", "", false, nil); nil == err {
	//			log.Println(resp.StatusCode, s1)
	//		} else {
	//			if n == 8081 {
	//				log.Println(err)
	//			}
	//		}
	//	}(i)
	//
	//}
	//Wg.Wait()
}
