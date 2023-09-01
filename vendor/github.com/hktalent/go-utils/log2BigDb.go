package go_utils

import "log"

// 记录日志到 大数据搜索引擎
func SendEsLog(m1 interface{}) {
	if 0 == len(EsUrl) {
		return
	}
	szId := "xxx"
	SendReq(&m1, szId, ESaveType(GetVal("toolType")))
}

var bOk = make(chan struct{})
var bDo = make(chan struct{}, 1)
var oR = make(chan interface{}, 5000)

func DoSaves() {
	var n = len(oR)
	var oS = make([]interface{}, n)
	for n > 0 {
		oS = append(oS, <-oR)
		n--
	}
	if 0 < len(oS) {
		DoSyncFunc(func() {
			SendEsLog(&oS)
			log.Println("DoSaves", n)
		})
	}
}

func PushLog(o interface{}) {
	oR <- o
}

func DoRunning() {
	defer DoSaves()
	for {
		select {
		case <-oR:
			if 5000 <= len(oR) {
				bDo <- struct{}{}
			}
		case <-bOk:
			return
		case <-bDo:
			DoSaves()
		}
	}
}

func CloseLogBigDb() {
	DoSaves()
	close(bOk)
	defer func() {
		close(bDo)
	}()
}
