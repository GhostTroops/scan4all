package go_utils

// 记录日志到 大数据搜索引擎
func SendEsLog(m1 interface{}) {
	if 0 == len(EsUrl) {
		return
	}
	szId := "xxx"
	SendReq(&m1, szId, ESaveType(GetVal("toolType")))

}

var bOk = make(chan struct{})
var bDo = make(chan struct{})
var oR = make(chan interface{}, 5000)

func DoSaves() {
	var n = len(oR)
	var oS = make([]interface{}, n)
	for n > 0 {
		oS = append(oS, <-oR)
		n--
	}
	DoSyncFunc(func() {
		SendEsLog(&oS)
	})
}

func PushLog(o interface{}) {
	oR <- o
	if 5000 <= len(oR) {
		bDo <- struct{}{}
	}
}

func DoRunning() {
	defer DoSaves()
	for {
		select {
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
		close(oR)
	}()
}
